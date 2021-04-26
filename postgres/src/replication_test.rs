use crate::replication::LogicalReplicationIter;
use crate::{Client, SimpleQueryMessage};
use fallible_iterator::FallibleIterator;
use postgres_protocol::message::backend::{
    LogicalReplicationMessage, ReplicationMessage, TupleData,
};
use std::time::SystemTime;
use tokio_postgres::types::PgLsn;
use tokio_postgres::NoTls;

#[test]
fn replication() {
    use LogicalReplicationMessage::{Begin, Commit, Insert};
    use ReplicationMessage::{PrimaryKeepAlive, XLogData};
    use SimpleQueryMessage::Row;

    let mut client = Client::connect(
        "host=localhost port=5433 user=postgres replication=database",
        NoTls,
    )
    .unwrap();

    client
        .simple_query("DROP TABLE IF EXISTS test_logical_replication")
        .unwrap();
    client
        .simple_query("CREATE TABLE test_logical_replication(i int)")
        .unwrap();
    let res = client
        .simple_query("SELECT 'test_logical_replication'::regclass::oid")
        .unwrap();
    let rel_id: u32 = if let Row(row) = &res[0] {
        row.get("oid").unwrap().parse().unwrap()
    } else {
        panic!("unexpeced query message");
    };

    client
        .simple_query("DROP PUBLICATION IF EXISTS test_pub")
        .unwrap();
    client
        .simple_query("CREATE PUBLICATION test_pub FOR ALL TABLES")
        .unwrap();

    let slot = "test_logical_slot";

    let query = format!(
        r#"CREATE_REPLICATION_SLOT {:?} TEMPORARY LOGICAL "pgoutput""#,
        slot
    );
    let slot_query = client.simple_query(&query).unwrap();
    let lsn = if let Row(row) = &slot_query[0] {
        row.get("consistent_point").unwrap()
    } else {
        panic!("unexpeced query message");
    };

    // issue a query that will appear in the slot's stream since it happened after its creation
    client
        .simple_query("INSERT INTO test_logical_replication VALUES (42)")
        .unwrap();

    let options = r#"("proto_version" '1', "publication_names" 'test_pub')"#;
    let query = format!(
        r#"START_REPLICATION SLOT {:?} LOGICAL {} {}"#,
        slot, lsn, options
    );
    let copy_stream = client.copy_both_simple(query.as_str()).unwrap();

    let mut stream = LogicalReplicationIter::new(copy_stream);

    // verify that we can observe the transaction in the replication stream
    let begin = loop {
        match stream.next() {
            Ok(Some(XLogData(body))) => {
                if let Begin(begin) = body.into_data() {
                    break begin;
                }
            }
            Ok(Some(_)) => (),
            Ok(None) => panic!("unexpected replication stream end"),
            Err(_) => panic!("unexpected replication stream error"),
        }
    };

    let insert = loop {
        match stream.next() {
            Ok(Some(XLogData(body))) => {
                if let Insert(insert) = body.into_data() {
                    break insert;
                }
            }
            Ok(Some(_)) => (),
            Ok(None) => panic!("unexpected replication stream end"),
            Err(_) => panic!("unexpected replication stream error"),
        }
    };

    let commit = loop {
        match stream.next() {
            Ok(Some(XLogData(body))) => {
                if let Commit(commit) = body.into_data() {
                    break commit;
                }
            }
            Ok(Some(_)) => (),
            Ok(None) => panic!("unexpected replication stream end"),
            Err(_) => panic!("unexpected replication stream error"),
        }
    };

    assert_eq!(begin.final_lsn(), commit.commit_lsn());
    assert_eq!(insert.rel_id(), rel_id);

    let tuple_data = insert.tuple().tuple_data();
    assert_eq!(tuple_data.len(), 1);
    assert!(matches!(tuple_data[0], TupleData::Text(_)));
    if let TupleData::Text(data) = &tuple_data[0] {
        assert_eq!(data, &b"42"[..]);
    }

    // Send a standby status update and require a keep alive response
    let lsn: PgLsn = lsn.parse().unwrap();
    stream
        .standby_status_update(lsn, lsn, lsn, SystemTime::now(), 1)
        .unwrap();
    loop {
        match stream.next() {
            Ok(Some(PrimaryKeepAlive(_))) => break,
            Ok(Some(_)) => (),
            Ok(None) => panic!("unexpected replication stream end"),
            Err(e) => panic!("unexpected replication stream error: {}", e),
        }
    }
}
