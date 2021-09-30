use crate::client::{InnerClient, Responses};
use crate::codec::FrontendMessage;
use crate::connection::RequestMessages;
use crate::{simple_query, Error};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::channel::mpsc;
use futures::future;
use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use log::debug;
use pin_project_lite::pin_project;
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use postgres_protocol::message::frontend::CopyData;
use std::marker::{PhantomData, PhantomPinned};
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) enum CopyBothMessage {
    Message(FrontendMessage),
    Done,
}

pub struct CopyBothReceiver {
    receiver: mpsc::Receiver<CopyBothMessage>,
    done: bool,
}

impl CopyBothReceiver {
    pub(crate) fn new(receiver: mpsc::Receiver<CopyBothMessage>) -> CopyBothReceiver {
        CopyBothReceiver {
            receiver,
            done: false,
        }
    }
}

impl Stream for CopyBothReceiver {
    type Item = FrontendMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<FrontendMessage>> {
        if self.done {
            return Poll::Ready(None);
        }

        match ready!(self.receiver.poll_next_unpin(cx)) {
            Some(CopyBothMessage::Message(message)) => Poll::Ready(Some(message)),
            Some(CopyBothMessage::Done) => {
                self.done = true;
                let mut buf = BytesMut::new();
                frontend::copy_done(&mut buf);
                frontend::sync(&mut buf);
                Poll::Ready(Some(FrontendMessage::Raw(buf.freeze())))
            }
            None => {
                self.done = true;
                let mut buf = BytesMut::new();
                frontend::copy_fail("", &mut buf).unwrap();
                frontend::sync(&mut buf);
                Poll::Ready(Some(FrontendMessage::Raw(buf.freeze())))
            }
        }
    }
}

enum SinkState {
    Active,
    Closing,
    Reading,
}

pin_project! {
    /// A sink & stream for `CopyBoth` replication  messages
    ///
    /// The copy *must* be explicitly completed via the `Sink::close` or `finish` methods. If it is
    /// not, the copy will be aborted.
    ///
    /// The duplex can be split into the separate sink and stream with the [`split`] method. When
    /// using this, they must be re-joined before finishing in order to properly complete the copy.
    ///
    /// Both the implementation of [`Stream`] and [`Sink`] provide access to the bytes wrapped
    /// inside of the `CopyData` wrapper.
    ///
    /// [`split`]: Self::split
    pub struct CopyBothDuplex<T> {
        #[pin]
        sender: mpsc::Sender<CopyBothMessage>,
        responses: Responses,
        buf: BytesMut,
        state: SinkState,
        #[pin]
        _p: PhantomPinned,
        _p2: PhantomData<T>,
    }
}

impl<T> CopyBothDuplex<T>
where
    T: Buf + 'static + Send,
{
    pub(crate) fn new(sender: mpsc::Sender<CopyBothMessage>, responses: Responses) -> Self {
        Self {
            sender,
            responses,
            buf: BytesMut::new(),
            state: SinkState::Active,
            _p: PhantomPinned,
            _p2: PhantomData,
        }
    }

    /// A poll-based version of `finish`.
    pub fn poll_finish(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        loop {
            match self.state {
                SinkState::Active => {
                    ready!(self.as_mut().poll_flush(cx))?;
                    let mut this = self.as_mut().project();
                    ready!(this.sender.as_mut().poll_ready(cx)).map_err(|_| Error::closed())?;
                    this.sender
                        .start_send(CopyBothMessage::Done)
                        .map_err(|_| Error::closed())?;
                    *this.state = SinkState::Closing;
                }
                SinkState::Closing => {
                    let this = self.as_mut().project();
                    ready!(this.sender.poll_close(cx)).map_err(|_| Error::closed())?;
                    *this.state = SinkState::Reading;
                }
                SinkState::Reading => {
                    let this = self.as_mut().project();
                    match ready!(this.responses.poll_next(cx))? {
                        Message::CommandComplete(body) => {
                            let rows = body
                                .tag()
                                .map_err(Error::parse)?
                                .rsplit(' ')
                                .next()
                                .unwrap()
                                .parse()
                                .unwrap_or(0);
                            return Poll::Ready(Ok(rows));
                        }
                        _ => return Poll::Ready(Err(Error::unexpected_message())),
                    }
                }
            }
        }
    }

    /// Completes the copy, returning the number of rows inserted.
    ///
    /// The `Sink::close` method is equivalent to `finish`, except that it does not return the
    /// number of rows.
    pub async fn finish(mut self: Pin<&mut Self>) -> Result<u64, Error> {
        future::poll_fn(|cx| self.as_mut().poll_finish(cx)).await
    }

    /// Splits the streams into distinct [`Sink`] and [`Stream`] components
    ///
    /// Please note that there must be an eventual call to [`join`] the two components in order to
    /// properly close the connection with [`finish`]; no corresponding method exists for the two
    /// halves alone.
    ///
    /// [`join`]: Self::join
    /// [`finish`]: Self::finish
    pub fn split(self) -> (Sender<T>, Receiver) {
        let send = Sender {
            sender: self.sender,
            buf: self.buf,
            state: self.state,
            marker: PhantomData,
            closed: false,
        };

        let recv = Receiver {
            responses: self.responses,
        };

        (send, recv)
    }

    /// Joins the two halves of a `CopyBothDuplex` after a call to [`split`]
    ///
    /// Note: We do not check that the sender and recevier originated from the same
    /// [`CopyBothDuplex`]. If they did not, unexpected behavior *will* occur.
    ///
    /// ## Panics
    ///
    /// If the sender has already been closed, this function will panic.
    ///
    /// [`split`]: Self::split
    pub fn join(send: Sender<T>, recv: Receiver) -> Self {
        assert!(!send.closed);

        CopyBothDuplex {
            sender: send.sender,
            responses: recv.responses,
            buf: send.buf,
            state: send.state,
            _p: PhantomPinned,
            _p2: PhantomData,
        }
    }
}

impl<T> Stream for CopyBothDuplex<T> {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match ready!(this.responses.poll_next(cx)?) {
            Message::CopyData(body) => Poll::Ready(Some(Ok(body.into_bytes()))),
            Message::CopyDone => Poll::Ready(None),
            Message::ErrorResponse(body) => Poll::Ready(Some(Err(Error::db(body)))),
            _ => Poll::Ready(Some(Err(Error::unexpected_message()))),
        }
    }
}

impl<T> Sink<T> for CopyBothDuplex<T>
where
    T: Buf + 'static + Send,
{
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project()
            .sender
            .poll_ready(cx)
            .map_err(|_| Error::closed())
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Error> {
        let this = self.project();

        let data: Box<dyn Buf + Send> = if item.remaining() > 4096 {
            if this.buf.is_empty() {
                Box::new(item)
            } else {
                Box::new(this.buf.split().freeze().chain(item))
            }
        } else {
            this.buf.put(item);
            if this.buf.len() > 4096 {
                Box::new(this.buf.split().freeze())
            } else {
                return Ok(());
            }
        };

        let data = CopyData::new(data).map_err(Error::encode)?;
        this.sender
            .start_send(CopyBothMessage::Message(FrontendMessage::CopyData(data)))
            .map_err(|_| Error::closed())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut this = self.project();

        if !this.buf.is_empty() {
            ready!(this.sender.as_mut().poll_ready(cx)).map_err(|_| Error::closed())?;
            let data: Box<dyn Buf + Send> = Box::new(this.buf.split().freeze());
            let data = CopyData::new(data).map_err(Error::encode)?;
            this.sender
                .as_mut()
                .start_send(CopyBothMessage::Message(FrontendMessage::CopyData(data)))
                .map_err(|_| Error::closed())?;
        }

        this.sender.poll_flush(cx).map_err(|_| Error::closed())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_finish(cx).map_ok(|_| ())
    }
}

pin_project! {
    /// The receiving half of a [`CopyBothDuplex`]
    ///
    /// Receiving the next message is done through the [`Stream`] implementation.
    pub struct Receiver {
        responses: Responses,
    }
}

pin_project! {
    /// The sending half of a [`CopyBothDuplex`]
    ///
    /// Sending each message is done through the [`Sink`] implementation.
    pub struct Sender<T> {
        #[pin]
        sender: mpsc::Sender<CopyBothMessage>,
        buf: BytesMut,
        state: SinkState,
        marker: PhantomData<T>,
        // True iff the sink has been closed. Causes further operations to panic.
        closed: bool,
    }
}

impl Stream for Receiver {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match ready!(this.responses.poll_next(cx)?) {
            Message::CopyData(body) => Poll::Ready(Some(Ok(body.into_bytes()))),
            Message::CopyDone => Poll::Ready(None),
            Message::ErrorResponse(body) => Poll::Ready(Some(Err(Error::db(body)))),
            _ => Poll::Ready(Some(Err(Error::unexpected_message()))),
        }
    }
}

impl<T> Sink<T> for Sender<T>
where
    T: Buf + 'static + Send,
{
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project()
            .sender
            .poll_ready(cx)
            .map_err(|_| Error::closed())
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Error> {
        assert!(!self.closed);

        let this = self.project();

        let data: Box<dyn Buf + Send> = if item.remaining() > 4096 {
            if this.buf.is_empty() {
                Box::new(item)
            } else {
                Box::new(this.buf.split().freeze().chain(item))
            }
        } else {
            this.buf.put(item);
            if this.buf.len() > 4096 {
                Box::new(this.buf.split().freeze())
            } else {
                return Ok(());
            }
        };

        let data = CopyData::new(data).map_err(Error::encode)?;
        this.sender
            .start_send(CopyBothMessage::Message(FrontendMessage::CopyData(data)))
            .map_err(|_| Error::closed())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut this = self.project();

        if !this.buf.is_empty() {
            ready!(this.sender.as_mut().poll_ready(cx)).map_err(|_| Error::closed())?;
            let data: Box<dyn Buf + Send> = Box::new(this.buf.split().freeze());
            let data = CopyData::new(data).map_err(Error::encode)?;
            this.sender
                .as_mut()
                .start_send(CopyBothMessage::Message(FrontendMessage::CopyData(data)))
                .map_err(|_| Error::closed())?;
        }

        this.sender.poll_flush(cx).map_err(|_| Error::closed())
    }

    // Closing the sink "normally" will just abort the copy.
    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

pub async fn copy_both_simple<T>(
    client: &InnerClient,
    query: &str,
) -> Result<CopyBothDuplex<T>, Error>
where
    T: Buf + 'static + Send,
{
    debug!("executing copy both query {}", query);

    let buf = simple_query::encode(client, query)?;

    let (mut sender, receiver) = mpsc::channel(1);
    let receiver = CopyBothReceiver::new(receiver);
    let mut responses = client.send(RequestMessages::CopyBoth(receiver))?;

    sender
        .send(CopyBothMessage::Message(FrontendMessage::Raw(buf)))
        .await
        .map_err(|_| Error::closed())?;

    match responses.next().await? {
        Message::CopyBothResponse(_) => {}
        _ => return Err(Error::unexpected_message()),
    }

    Ok(CopyBothDuplex::new(sender, responses))
}
