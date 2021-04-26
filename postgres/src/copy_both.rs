use crate::connection::ConnectionRef;
use crate::lazy_pin::LazyPin;
use bytes::{Buf, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::io::{self, BufRead, Read};
use tokio_postgres::{CopyBothDuplex, Error};

/// The reader/writer returned by the `copy_both_simple` method.
pub struct CopyBoth<'a> {
    pub(crate) connection: ConnectionRef<'a>,
    pub(crate) stream_sink: LazyPin<CopyBothDuplex<Bytes>>,
    buf: BytesMut,
    cur: Bytes,
}

impl<'a> CopyBoth<'a> {
    pub(crate) fn new(
        connection: ConnectionRef<'a>,
        duplex: CopyBothDuplex<Bytes>,
    ) -> CopyBoth<'a> {
        CopyBoth {
            connection,
            stream_sink: LazyPin::new(duplex),
            buf: BytesMut::new(),
            cur: Bytes::new(),
        }
    }

    /// Completes the copy, returning the number of rows written.
    ///
    /// If this is not called, the copy will be aborted.
    pub fn finish(mut self) -> Result<u64, Error> {
        self.flush_inner()?;
        self.connection.block_on(self.stream_sink.pinned().finish())
    }

    fn flush_inner(&mut self) -> Result<(), Error> {
        if self.buf.is_empty() {
            return Ok(());
        }

        self.connection
            .block_on(self.stream_sink.pinned().send(self.buf.split().freeze()))
    }
}

impl Read for CopyBoth<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let b = self.fill_buf()?;
        let len = usize::min(buf.len(), b.len());
        buf[..len].copy_from_slice(&b[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl BufRead for CopyBoth<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while !self.cur.has_remaining() {
            let mut stream = self.stream_sink.pinned();
            match self
                .connection
                .block_on(async { stream.next().await.transpose() })
            {
                Ok(Some(cur)) => self.cur = cur,
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                Ok(None) => break,
            };
        }

        Ok(&self.cur)
    }

    fn consume(&mut self, amt: usize) {
        self.cur.advance(amt);
    }
}
