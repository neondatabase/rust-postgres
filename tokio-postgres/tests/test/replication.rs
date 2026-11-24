use bytes::Bytes;
use futures_util::{Sink, SinkExt, StreamExt};
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use postgres_protocol::message::backend::LogicalReplicationMessage::{
    Begin, Commit, Delete, Insert, Update,
};
use postgres_protocol::message::backend::ReplicationMessage::*;
use postgres_protocol::message::backend::TupleData;
use postgres_protocol::PG_EPOCH;
use postgres_types::PgLsn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_postgres::replication::{LogicalReplicationStream, ReplicationStream};
use tokio_postgres::SimpleQueryMessage::Row;
use tokio_postgres::{Client, Config, NoTls};

async fn read_frame(stream: &mut TcpStream) -> (u8, Bytes) {
    let tag = stream.read_u8().await.unwrap();
    let len = stream.read_u32().await.unwrap() as usize;
    let mut body = vec![0; len - 4];
    stream.read_exact(&mut body).await.unwrap();
    (tag, Bytes::from(body))
}

async fn write_frame(stream: &mut TcpStream, tag: u8, body: &[u8]) {
    stream.write_u8(tag).await.unwrap();
    stream.write_u32((body.len() + 4) as u32).await.unwrap();
    stream.write_all(body).await.unwrap();
}

async fn copy_both_connection(
    initial_message: Option<Bytes>,
) -> (Client, ReplicationStream, JoinHandle<Bytes>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        let startup_len = socket.read_u32().await.unwrap() as usize;
        let mut startup = vec![0; startup_len - 4];
        socket.read_exact(&mut startup).await.unwrap();

        write_frame(&mut socket, b'R', &[0; 4]).await;
        write_frame(&mut socket, b'Z', b"I").await;

        let (tag, query) = read_frame(&mut socket).await;
        assert_eq!(tag, b'Q');
        assert_eq!(&query[..], b"START_REPLICATION\0");
        write_frame(&mut socket, b'W', &[0, 0, 0]).await;

        if let Some(message) = initial_message {
            write_frame(&mut socket, b'd', &message).await;
        }

        let (tag, feedback) = read_frame(&mut socket).await;
        assert_eq!(tag, b'd');
        feedback
    });

    let socket = TcpStream::connect(address).await.unwrap();
    let config = "user=postgres replication=true".parse::<Config>().unwrap();
    let (client, connection) = config.connect_raw(socket, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let copy_stream = client
        .copy_both_simple::<Bytes>("START_REPLICATION")
        .await
        .unwrap();
    (client, ReplicationStream::new(copy_stream), server)
}

#[tokio::test]
async fn copy_both_split_large_frames_and_close() {
    time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let startup_len = socket.read_u32().await.unwrap() as usize;
            let mut startup = vec![0; startup_len - 4];
            socket.read_exact(&mut startup).await.unwrap();

            write_frame(&mut socket, b'R', &[0; 4]).await;
            write_frame(&mut socket, b'Z', b"I").await;

            let (tag, query) = read_frame(&mut socket).await;
            assert_eq!(tag, b'Q');
            assert_eq!(&query[..], b"START_REPLICATION\0");
            write_frame(&mut socket, b'W', &[0, 0, 0]).await;

            write_frame(&mut socket, b'd', &vec![0x5a; 5_000]).await;
            write_frame(&mut socket, b'c', &[]).await;

            let mut frames = Vec::new();
            let (tag, body) = loop {
                let (tag, frame) = read_frame(&mut socket).await;
                if tag != b'd' {
                    break (tag, frame);
                }
                frames.push(frame);
            };
            assert_eq!(frames.len(), 3, "unexpected CopyData frames: {frames:?}");
            assert_eq!(frames[0].len(), 5_000);
            assert!(frames[0].iter().all(|byte| *byte == 0x11));
            assert_eq!(frames[1].len(), 5_002);
            assert_eq!(&frames[1][..2], b"ab");
            assert!(frames[1][2..].iter().all(|byte| *byte == 0x22));
            assert_eq!(frames[2].len(), 6_000);
            assert!(frames[2][..3_000].iter().all(|byte| *byte == 0x33));
            assert!(frames[2][3_000..].iter().all(|byte| *byte == 0x44));

            assert_eq!(tag, b'c');
            assert!(body.is_empty());
            let (tag, body) = read_frame(&mut socket).await;
            assert_eq!(tag, b'S');
            assert!(body.is_empty());

            write_frame(&mut socket, b'C', b"COPY 7\0").await;
            write_frame(&mut socket, b'Z', b"I").await;
        });

        let socket = TcpStream::connect(address).await.unwrap();
        let config = "user=postgres replication=true".parse::<Config>().unwrap();
        let (client, connection) = config.connect_raw(socket, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let copy_stream = client
            .copy_both_simple::<Bytes>("START_REPLICATION")
            .await
            .unwrap();
        let (mut sink, mut stream) = copy_stream.split();

        let received = stream.next().await.unwrap().unwrap();
        assert_eq!(received.len(), 5_000);
        assert!(received.iter().all(|byte| *byte == 0x5a));
        assert!(stream.next().await.is_none());

        sink.send(Bytes::from(vec![0x11; 5_000])).await.unwrap();
        futures_util::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut sink)
            .start_send(Bytes::from_static(b"ab"))
            .unwrap();
        futures_util::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut sink)
            .start_send(Bytes::from(vec![0x22; 5_000]))
            .unwrap();
        futures_util::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut sink)
            .start_send(Bytes::from(vec![0x33; 3_000]))
            .unwrap();
        futures_util::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut sink)
            .start_send(Bytes::from(vec![0x44; 3_000]))
            .unwrap();
        sink.close().await.unwrap();
        server.await.unwrap();

        drop(sink);
        drop(stream);
        drop(client);
    })
    .await
    .expect("split CopyBoth test timed out");
}

#[tokio::test]
async fn copy_both_finish_returns_row_count() {
    time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let startup_len = socket.read_u32().await.unwrap() as usize;
            let mut startup = vec![0; startup_len - 4];
            socket.read_exact(&mut startup).await.unwrap();

            write_frame(&mut socket, b'R', &[0; 4]).await;
            write_frame(&mut socket, b'Z', b"I").await;

            let (tag, query) = read_frame(&mut socket).await;
            assert_eq!(tag, b'Q');
            assert_eq!(&query[..], b"START_REPLICATION\0");
            write_frame(&mut socket, b'W', &[0, 0, 0]).await;

            let (tag, body) = read_frame(&mut socket).await;
            assert_eq!(tag, b'c');
            assert!(body.is_empty());
            let (tag, body) = read_frame(&mut socket).await;
            assert_eq!(tag, b'S');
            assert!(body.is_empty());

            write_frame(&mut socket, b'C', b"COPY 7\0").await;
            write_frame(&mut socket, b'Z', b"I").await;
        });

        let socket = TcpStream::connect(address).await.unwrap();
        let config = "user=postgres replication=true".parse::<Config>().unwrap();
        let (client, connection) = config.connect_raw(socket, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let copy_stream = client
            .copy_both_simple::<Bytes>("START_REPLICATION")
            .await
            .unwrap();
        tokio::pin!(copy_stream);
        assert_eq!(copy_stream.as_mut().finish().await.unwrap(), 7);
        server.await.unwrap();

        drop(copy_stream);
        drop(client);
    })
    .await
    .expect("CopyBoth finish test timed out");
}

#[tokio::test]
async fn interpreted_wal_and_zenith_feedback_match_safekeeper_protocol() {
    time::timeout(Duration::from_secs(5), async {
        // This is pq_proto::BeMessage::InterpretedWalRecords without its CopyData header.
        let message = Bytes::from_static(
            b"0\x01\x02\x03\x04\x05\x06\x07\x08\
              \x11\x12\x13\x14\x15\x16\x17\x18\xde\xad\xbe\xef",
        );
        let (client, stream, server) = copy_both_connection(Some(message)).await;
        tokio::pin!(stream);

        let message = stream.next().await.unwrap().unwrap();
        let body = match message {
            RawInterpretedWalRecords(body) => body,
            _ => panic!("expected interpreted WAL records"),
        };
        assert_eq!(body.streaming_lsn(), 0x0102_0304_0506_0708);
        assert_eq!(body.commit_lsn(), 0x1112_1314_1516_1718);
        assert_eq!(body.data(), &b"\xde\xad\xbe\xef"[..]);

        stream
            .as_mut()
            .zenith_status_update(0x0102_0304_0506_0708, b"\xde\xad\xbe\xef")
            .await
            .unwrap();
        let feedback = server.await.unwrap();
        assert_eq!(
            &feedback[..],
            b"z\x01\x02\x03\x04\x05\x06\x07\x08\xde\xad\xbe\xef"
        );

        drop(stream);
        drop(client);
    })
    .await
    .expect("interpreted WAL test timed out");
}

struct HotStandbyFeedbackCase {
    name: &'static str,
    timestamp_micros: i64,
    global_xmin: u32,
    global_xmin_epoch: u32,
    catalog_xmin: u32,
    catalog_xmin_epoch: u32,
    expected: &'static [u8],
}

async fn assert_hot_standby_feedback(case: HotStandbyFeedbackCase) {
    time::timeout(Duration::from_secs(5), async {
        let (client, stream, server) = copy_both_connection(None).await;
        tokio::pin!(stream);
        let timestamp = if case.timestamp_micros >= 0 {
            *PG_EPOCH + Duration::from_micros(case.timestamp_micros as u64)
        } else {
            *PG_EPOCH - Duration::from_micros(case.timestamp_micros.unsigned_abs())
        };

        stream
            .as_mut()
            .hot_standby_feedback(
                timestamp,
                case.global_xmin,
                case.global_xmin_epoch,
                case.catalog_xmin,
                case.catalog_xmin_epoch,
            )
            .await
            .unwrap();
        let feedback = server.await.unwrap();
        assert_eq!(&feedback[..], case.expected, "{}", case.name);

        drop(stream);
        drop(client);
    })
    .await
    .unwrap_or_else(|_| panic!("{} timed out", case.name));
}

#[tokio::test]
async fn hot_standby_feedback_matches_postgres_walreceiver_protocol() {
    // Upstream walreceiver.c sends the timestamp, each 32-bit XID, then its epoch.
    let cases = [
        HotStandbyFeedbackCase {
            name: "distinct transaction IDs",
            timestamp_micros: 1_234_567,
            global_xmin: 0x0102_0304,
            global_xmin_epoch: 0x0506_0708,
            catalog_xmin: 0x1112_1314,
            catalog_xmin_epoch: 0x1516_1718,
            expected: b"h\0\0\0\0\0\x12\xd6\x87\
                        \x01\x02\x03\x04\x05\x06\x07\x08\
                        \x11\x12\x13\x14\x15\x16\x17\x18",
        },
        HotStandbyFeedbackCase {
            name: "zero transaction IDs",
            timestamp_micros: 0,
            global_xmin: 0,
            global_xmin_epoch: 0,
            catalog_xmin: 0,
            catalog_xmin_epoch: 0,
            expected: b"h\0\0\0\0\0\0\0\0\
                        \0\0\0\0\0\0\0\0\
                        \0\0\0\0\0\0\0\0",
        },
        HotStandbyFeedbackCase {
            name: "catalog transaction ID only",
            timestamp_micros: 1,
            global_xmin: 0,
            global_xmin_epoch: 0,
            catalog_xmin: 0x1112_1314,
            catalog_xmin_epoch: 0x1516_1718,
            expected: b"h\0\0\0\0\0\0\0\x01\
                        \0\0\0\0\0\0\0\0\
                        \x11\x12\x13\x14\x15\x16\x17\x18",
        },
        HotStandbyFeedbackCase {
            name: "maximum field values",
            timestamp_micros: i64::MAX,
            global_xmin: u32::MAX,
            global_xmin_epoch: u32::MAX,
            catalog_xmin: u32::MAX,
            catalog_xmin_epoch: u32::MAX,
            expected: b"h\x7f\xff\xff\xff\xff\xff\xff\xff\
                        \xff\xff\xff\xff\xff\xff\xff\xff\
                        \xff\xff\xff\xff\xff\xff\xff\xff",
        },
        HotStandbyFeedbackCase {
            name: "timestamp before the PostgreSQL epoch",
            timestamp_micros: -1,
            global_xmin: 0,
            global_xmin_epoch: 0,
            catalog_xmin: 0,
            catalog_xmin_epoch: 0,
            expected: b"h\xff\xff\xff\xff\xff\xff\xff\xff\
                        \0\0\0\0\0\0\0\0\
                        \0\0\0\0\0\0\0\0",
        },
    ];

    for case in cases {
        assert_hot_standby_feedback(case).await;
    }
}

#[tokio::test]
async fn test_replication() {
    test_replication_impl(false /*binary*/).await;
    test_replication_impl(true /*binary*/).await;
}

async fn test_replication_impl(binary: bool) {
    // form SQL connection
    let conninfo = "host=127.0.0.1 port=5433 user=postgres replication=database";
    let (client, connection) = tokio_postgres::connect(conninfo, NoTls).await.unwrap();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    client
        .simple_query("DROP TABLE IF EXISTS test_logical_replication")
        .await
        .unwrap();
    client
        .simple_query("CREATE TABLE test_logical_replication(i int, nullable_text text)")
        .await
        .unwrap();
    client
        .simple_query("ALTER TABLE test_logical_replication REPLICA IDENTITY FULL")
        .await
        .unwrap();
    let res = client
        .simple_query("SELECT 'test_logical_replication'::regclass::oid")
        .await
        .unwrap();
    let rel_id: u32 = if let Row(row) = &res[0] {
        row.get("oid").unwrap().parse().unwrap()
    } else {
        panic!("unexpeced query message");
    };

    client
        .simple_query("DROP PUBLICATION IF EXISTS test_pub")
        .await
        .unwrap();
    client
        .simple_query("CREATE PUBLICATION test_pub FOR ALL TABLES")
        .await
        .unwrap();

    let slot = "test_logical_slot";

    let query = format!(
        r#"CREATE_REPLICATION_SLOT {:?} TEMPORARY LOGICAL "pgoutput""#,
        slot
    );
    let slot_query = client.simple_query(&query).await.unwrap();
    let lsn = if let Row(row) = &slot_query[0] {
        row.get("consistent_point").unwrap()
    } else {
        panic!("unexpeced query message");
    };

    // issue a query that will appear in the slot's stream since it happened after its creation
    client
        .simple_query("INSERT INTO test_logical_replication VALUES (42, NULL)")
        .await
        .unwrap();
    client
        .simple_query("UPDATE test_logical_replication SET nullable_text = 'updated'")
        .await
        .unwrap();
    client
        .simple_query("DELETE FROM test_logical_replication")
        .await
        .unwrap();

    let options = format!(
        "(\"proto_version\" '1', \"publication_names\" 'test_pub', \"binary\" '{}')",
        binary
    );
    let query = format!(
        r#"START_REPLICATION SLOT {:?} LOGICAL {} {}"#,
        slot, lsn, options
    );
    let copy_stream = client
        .copy_both_simple::<bytes::Bytes>(&query)
        .await
        .unwrap();

    let stream = LogicalReplicationStream::new(copy_stream);
    tokio::pin!(stream);

    // verify that we can observe the transaction in the replication stream
    let begin = loop {
        match stream.next().await {
            Some(Ok(XLogData(body))) => {
                if let Begin(begin) = body.into_data() {
                    break begin;
                }
            }
            Some(Ok(_)) => (),
            Some(Err(_)) => panic!("unexpected replication stream error"),
            None => panic!("unexpected replication stream end"),
        }
    };
    let insert = loop {
        match stream.next().await {
            Some(Ok(XLogData(body))) => {
                if let Insert(insert) = body.into_data() {
                    break insert;
                }
            }
            Some(Ok(_)) => (),
            Some(Err(_)) => panic!("unexpected replication stream error"),
            None => panic!("unexpected replication stream end"),
        }
    };

    let commit = loop {
        match stream.next().await {
            Some(Ok(XLogData(body))) => {
                if let Commit(commit) = body.into_data() {
                    break commit;
                }
            }
            Some(Ok(_)) => (),
            Some(Err(_)) => panic!("unexpected replication stream error"),
            None => panic!("unexpected replication stream end"),
        }
    };

    assert_eq!(begin.final_lsn(), commit.commit_lsn());
    assert_eq!(insert.rel_id(), rel_id);

    let tuple_data = insert.tuple().tuple_data();
    assert_eq!(tuple_data.len(), 2);
    match (&tuple_data[0], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"42"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &42i32.to_be_bytes()[..]),
        _ => unreachable!(),
    }
    assert!(matches!(tuple_data[1], TupleData::Null));

    let update = loop {
        match stream.next().await {
            Some(Ok(XLogData(body))) => {
                if let Update(update) = body.into_data() {
                    break update;
                }
            }
            Some(Ok(_)) => (),
            Some(Err(error)) => panic!("unexpected replication stream error: {}", error),
            None => panic!("unexpected replication stream end"),
        }
    };
    assert_eq!(update.rel_id(), rel_id);
    assert!(update.key_tuple().is_none());
    let old_tuple = update.old_tuple().unwrap().tuple_data();
    assert_eq!(old_tuple.len(), 2);
    match (&old_tuple[0], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"42"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &42i32.to_be_bytes()[..]),
        _ => unreachable!(),
    }
    assert!(matches!(old_tuple[1], TupleData::Null));
    let new_tuple = update.new_tuple().tuple_data();
    assert_eq!(new_tuple.len(), 2);
    match (&new_tuple[0], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"42"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &42i32.to_be_bytes()[..]),
        _ => unreachable!(),
    }
    match (&new_tuple[1], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"updated"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &b"updated"[..]),
        _ => unreachable!(),
    }

    let delete = loop {
        match stream.next().await {
            Some(Ok(XLogData(body))) => {
                if let Delete(delete) = body.into_data() {
                    break delete;
                }
            }
            Some(Ok(_)) => (),
            Some(Err(error)) => panic!("unexpected replication stream error: {}", error),
            None => panic!("unexpected replication stream end"),
        }
    };
    assert_eq!(delete.rel_id(), rel_id);
    assert!(delete.key_tuple().is_none());
    let old_tuple = delete.old_tuple().unwrap().tuple_data();
    assert_eq!(old_tuple.len(), 2);
    match (&old_tuple[0], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"42"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &42i32.to_be_bytes()[..]),
        _ => unreachable!(),
    }
    match (&old_tuple[1], binary) {
        (TupleData::Text(data), false) => assert_eq!(data, &b"updated"[..]),
        (TupleData::Binary(data), true) => assert_eq!(data, &b"updated"[..]),
        _ => unreachable!(),
    }

    // Send a standby status update and require a keep alive response
    let lsn: PgLsn = lsn.parse().unwrap();
    stream
        .as_mut()
        .standby_status_update(lsn, lsn, lsn, SystemTime::now(), 1)
        .await
        .unwrap();
    loop {
        match stream.next().await {
            Some(Ok(PrimaryKeepAlive(_))) => break,
            Some(Ok(_)) => (),
            Some(Err(e)) => panic!("unexpected replication stream error: {}", e),
            None => panic!("unexpected replication stream end"),
        }
    }
}
