//! Utilities for working with the PostgreSQL replication copy both format.

use crate::connection::ConnectionRef;
use crate::lazy_pin::LazyPin;
use crate::{CopyBoth, Error};
use bytes::Bytes;
use fallible_iterator::FallibleIterator;
use futures::Stream;
use postgres_protocol::message::backend::{LogicalReplicationMessage, ReplicationMessage};
use std::task::Poll;
use std::time::SystemTime;
use tokio_postgres::replication::{LogicalReplicationStream, ReplicationStream};
use tokio_postgres::types::PgLsn;

/// A type which deserializes the postgres replication protocol.
///
/// This type can be used with both physical and logical replication to get
/// access to the byte content of each replication message.
///
/// This is the sync (blocking) version of [`ReplicationStream`]
pub struct ReplicationIter<'a> {
    connection: ConnectionRef<'a>,
    stream: LazyPin<ReplicationStream>,
}

impl<'a> ReplicationIter<'a> {
    /// Creates a new `ReplicationIter`.
    pub fn new(copyboth: CopyBoth<'a>) -> Self {
        let unpinned_copyboth = copyboth
            .stream_sink
            .into_unpinned()
            .expect("copy-both stream has already been used");
        let stream = ReplicationStream::new(unpinned_copyboth);
        Self {
            connection: copyboth.connection,
            stream: LazyPin::new(stream),
        }
    }

    /// Send standby update to server.
    pub fn standby_status_update(
        &mut self,
        write_lsn: PgLsn,
        flush_lsn: PgLsn,
        apply_lsn: PgLsn,
        timestamp: SystemTime,
        reply: u8,
    ) -> Result<(), Error> {
        self.connection.block_on(
            self.stream
                .pinned()
                .standby_status_update(write_lsn, flush_lsn, apply_lsn, timestamp, reply),
        )
    }

    /// Send hot standby feedback message to server.
    pub fn hot_standby_feedback(
        &mut self,
        timestamp: SystemTime,
        global_xmin: u32,
        global_xmin_epoch: u32,
        catalog_xmin: u32,
        catalog_xmin_epoch: u32,
    ) -> Result<(), Error> {
        self.connection
            .block_on(self.stream.pinned().hot_standby_feedback(
                timestamp,
                global_xmin,
                global_xmin_epoch,
                catalog_xmin,
                catalog_xmin_epoch,
            ))
    }
}

impl<'a> FallibleIterator for ReplicationIter<'a> {
    type Item = ReplicationMessage<Bytes>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let pinstream = &mut self.stream;

        self.connection
            .poll_block_on(|cx, _, _| match pinstream.pinned().poll_next(cx) {
                Poll::Ready(x) => Poll::Ready(x.transpose()),
                Poll::Pending => Poll::Pending,
            })
    }
}

/// A type which deserializes the postgres logical replication protocol. This
/// type gives access to a high level representation of the changes in
/// transaction commit order.
///
/// This is the sync (blocking) version of [`LogicalReplicationStream`]
pub struct LogicalReplicationIter<'a> {
    connection: ConnectionRef<'a>,
    stream: LazyPin<LogicalReplicationStream>,
}

impl<'a> LogicalReplicationIter<'a> {
    /// Creates a new `ReplicationThing`.
    pub fn new(copyboth: CopyBoth<'a>) -> Self {
        let unpinned_copyboth = copyboth
            .stream_sink
            .into_unpinned()
            .expect("copy-both stream has already been used");
        let stream = LogicalReplicationStream::new(unpinned_copyboth);
        Self {
            connection: copyboth.connection,
            stream: LazyPin::new(stream),
        }
    }

    /// Send standby update to server.
    pub fn standby_status_update(
        &mut self,
        write_lsn: PgLsn,
        flush_lsn: PgLsn,
        apply_lsn: PgLsn,
        timestamp: SystemTime,
        reply: u8,
    ) -> Result<(), Error> {
        self.connection.block_on(
            self.stream
                .pinned()
                .standby_status_update(write_lsn, flush_lsn, apply_lsn, timestamp, reply),
        )
    }

    /// Send hot standby feedback message to server.
    pub fn hot_standby_feedback(
        &mut self,
        timestamp: SystemTime,
        global_xmin: u32,
        global_xmin_epoch: u32,
        catalog_xmin: u32,
        catalog_xmin_epoch: u32,
    ) -> Result<(), Error> {
        self.connection
            .block_on(self.stream.pinned().hot_standby_feedback(
                timestamp,
                global_xmin,
                global_xmin_epoch,
                catalog_xmin,
                catalog_xmin_epoch,
            ))
    }
}

impl<'a> FallibleIterator for LogicalReplicationIter<'a> {
    type Item = ReplicationMessage<LogicalReplicationMessage>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let pinstream = &mut self.stream;

        self.connection
            .poll_block_on(|cx, _, _| match pinstream.pinned().poll_next(cx) {
                Poll::Ready(x) => Poll::Ready(x.transpose()),
                Poll::Pending => Poll::Pending,
            })
    }
}
