use std::{net::SocketAddr, sync::Arc, time::Duration};

use chia_protocol::{
    Bytes32, ChiaProtocolMessage, CoinStateFilters, HeaderBlock, Message, PuzzleSolutionResponse,
    RegisterForCoinUpdates, RegisterForPhUpdates, RejectBlockHeaders, RejectCoinState,
    RejectHeaderRequest, RejectPuzzleSolution, RejectPuzzleState, RequestBlockHeader,
    RequestBlockHeaders, RequestChildren, RequestCoinState, RequestPeers, RequestPuzzleSolution,
    RequestPuzzleState, RequestRemoveCoinSubscriptions, RequestRemovePuzzleSubscriptions,
    RequestTransaction, RespondBlockHeader, RespondBlockHeaders, RespondChildren, RespondCoinState,
    RespondPeers, RespondPuzzleSolution, RespondPuzzleState, RespondRemoveCoinSubscriptions,
    RespondRemovePuzzleSubscriptions, RespondToCoinUpdates, RespondToPhUpdates, RespondTransaction,
    SendTransaction, SpendBundle, TransactionAck,
};
use chia_traits::Streamable;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use tokio::{
    net::TcpStream,
    sync::{
        Mutex,
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::JoinHandle,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, warn};

use crate::{ClientError, RateLimiter, V2_RATE_LIMITS, request_map::RequestMap};

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use tokio_tungstenite::Connector;

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Sink = SplitSink<WebSocket, tungstenite::Message>;
type Stream = SplitStream<WebSocket>;
type Response<T, E> = std::result::Result<T, E>;

/// The number of unsolicited messages (such as `NewPeakWallet` and `CoinStateUpdate`) that are
/// buffered for the message receiver. Once it's full, new unsolicited messages are dropped until
/// the receiver catches up. Responses to requests don't go through this buffer.
pub const MESSAGE_BUFFER_SIZE: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PeerOptions {
    pub rate_limit_factor: f64,
    /// How long to wait for the handshake and for the response to each request before failing
    /// with [`ClientError::Timeout`]. If this is [`None`], they wait until the connection closes.
    pub request_timeout: Option<Duration>,
}

impl Default for PeerOptions {
    fn default() -> Self {
        Self {
            rate_limit_factor: 0.6,
            request_timeout: Some(Duration::from_mins(1)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer(Arc<PeerInner>);

#[derive(Debug)]
struct PeerInner {
    sink: Mutex<Sink>,
    inbound_handle: JoinHandle<()>,
    requests: Arc<RequestMap>,
    socket_addr: SocketAddr,
    outbound_rate_limiter: Mutex<RateLimiter>,
    request_timeout: Option<Duration>,
}

impl Peer {
    /// Connects to a peer using its IP address and port.
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub async fn connect(
        socket_addr: SocketAddr,
        connector: Connector,
        options: PeerOptions,
    ) -> Result<(Self, mpsc::Receiver<Message>), ClientError> {
        Self::connect_full_uri(&format!("wss://{socket_addr}/ws"), connector, options).await
    }

    /// Connects to a peer using its full websocket URI.
    /// For example, `wss://127.0.0.1:8444/ws`.
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub async fn connect_full_uri(
        uri: &str,
        connector: Connector,
        options: PeerOptions,
    ) -> Result<(Self, mpsc::Receiver<Message>), ClientError> {
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(uri, None, false, Some(connector))
                .await?;
        Self::from_websocket(ws, options)
    }

    /// Creates a peer from an existing websocket connection.
    /// The connection must be secured with TLS, so that the certificate can be hashed in a peer id.
    pub fn from_websocket(
        ws: WebSocket,
        options: PeerOptions,
    ) -> Result<(Self, mpsc::Receiver<Message>), ClientError> {
        let socket_addr = match ws.get_ref() {
            #[cfg(feature = "native-tls")]
            MaybeTlsStream::NativeTls(tls) => {
                let tls_stream = tls.get_ref();
                let tcp_stream = tls_stream.get_ref().get_ref();
                tcp_stream.peer_addr()?
            }
            #[cfg(feature = "rustls")]
            MaybeTlsStream::Rustls(tls) => {
                let (tcp_stream, _) = tls.get_ref();
                tcp_stream.peer_addr()?
            }
            MaybeTlsStream::Plain(plain) => plain.peer_addr()?,
            _ => return Err(ClientError::UnsupportedTls),
        };

        let (sink, stream) = ws.split();
        let (sender, receiver) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        let requests = Arc::new(RequestMap::new());
        let requests_clone = requests.clone();

        let inbound_handle = tokio::spawn(async move {
            if let Err(error) = handle_inbound_messages(stream, sender, &requests_clone).await {
                debug!("Error handling message: {error}");
            }

            // Nothing can respond to the pending requests anymore, so fail them now.
            requests_clone.close().await;
        });

        let peer = Self(Arc::new(PeerInner {
            sink: Mutex::new(sink),
            inbound_handle,
            requests,
            socket_addr,
            outbound_rate_limiter: Mutex::new(RateLimiter::new(
                false,
                60,
                options.rate_limit_factor,
                V2_RATE_LIMITS.clone(),
            )),
            request_timeout: options.request_timeout,
        }));

        Ok((peer, receiver))
    }

    /// The IP address and port of the peer connection.
    pub fn socket_addr(&self) -> SocketAddr {
        self.0.socket_addr
    }

    /// How long requests wait for a response, as configured in [`PeerOptions::request_timeout`].
    pub fn request_timeout(&self) -> Option<Duration> {
        self.0.request_timeout
    }

    pub async fn send_transaction(
        &self,
        spend_bundle: SpendBundle,
    ) -> Result<TransactionAck, ClientError> {
        self.request_infallible(SendTransaction::new(spend_bundle))
            .await
    }

    pub async fn request_puzzle_state(
        &self,
        puzzle_hashes: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
        filters: CoinStateFilters,
        subscribe_when_finished: bool,
    ) -> Result<Response<RespondPuzzleState, RejectPuzzleState>, ClientError> {
        self.request_fallible(RequestPuzzleState::new(
            puzzle_hashes,
            previous_height,
            header_hash,
            filters,
            subscribe_when_finished,
        ))
        .await
    }

    pub async fn request_coin_state(
        &self,
        coin_ids: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
        subscribe: bool,
    ) -> Result<Response<RespondCoinState, RejectCoinState>, ClientError> {
        self.request_fallible(RequestCoinState::new(
            coin_ids,
            previous_height,
            header_hash,
            subscribe,
        ))
        .await
    }

    pub async fn register_for_ph_updates(
        &self,
        puzzle_hashes: Vec<Bytes32>,
        min_height: u32,
    ) -> Result<RespondToPhUpdates, ClientError> {
        self.request_infallible(RegisterForPhUpdates::new(puzzle_hashes, min_height))
            .await
    }

    pub async fn register_for_coin_updates(
        &self,
        coin_ids: Vec<Bytes32>,
        min_height: u32,
    ) -> Result<RespondToCoinUpdates, ClientError> {
        self.request_infallible(RegisterForCoinUpdates::new(coin_ids, min_height))
            .await
    }

    pub async fn remove_puzzle_subscriptions(
        &self,
        puzzle_hashes: Option<Vec<Bytes32>>,
    ) -> Result<RespondRemovePuzzleSubscriptions, ClientError> {
        self.request_infallible(RequestRemovePuzzleSubscriptions::new(puzzle_hashes))
            .await
    }

    pub async fn remove_coin_subscriptions(
        &self,
        coin_ids: Option<Vec<Bytes32>>,
    ) -> Result<RespondRemoveCoinSubscriptions, ClientError> {
        self.request_infallible(RequestRemoveCoinSubscriptions::new(coin_ids))
            .await
    }

    pub async fn request_transaction(
        &self,
        transaction_id: Bytes32,
    ) -> Result<RespondTransaction, ClientError> {
        self.request_infallible(RequestTransaction::new(transaction_id))
            .await
    }

    pub async fn request_puzzle_and_solution(
        &self,
        coin_id: Bytes32,
        height: u32,
    ) -> Result<Response<PuzzleSolutionResponse, RejectPuzzleSolution>, ClientError> {
        match self
            .request_fallible::<RespondPuzzleSolution, _, _>(RequestPuzzleSolution::new(
                coin_id, height,
            ))
            .await?
        {
            Ok(response) => Ok(Ok(response.response)),
            Err(rejection) => Ok(Err(rejection)),
        }
    }

    pub async fn request_children(&self, coin_id: Bytes32) -> Result<RespondChildren, ClientError> {
        self.request_infallible(RequestChildren::new(coin_id)).await
    }

    pub async fn request_block_header(
        &self,
        height: u32,
    ) -> Result<Response<HeaderBlock, RejectHeaderRequest>, ClientError> {
        match self
            .request_fallible::<RespondBlockHeader, _, _>(RequestBlockHeader::new(height))
            .await?
        {
            Ok(response) => Ok(Ok(response.header_block)),
            Err(rejection) => Ok(Err(rejection)),
        }
    }

    /// Requests the header blocks from `start_height` to `end_height`, inclusive.
    /// Full nodes reject ranges of more than 128 blocks.
    pub async fn request_block_headers(
        &self,
        start_height: u32,
        end_height: u32,
        return_filter: bool,
    ) -> Result<Response<RespondBlockHeaders, RejectBlockHeaders>, ClientError> {
        self.request_fallible(RequestBlockHeaders::new(
            start_height,
            end_height,
            return_filter,
        ))
        .await
    }

    pub async fn request_peers(&self) -> Result<RespondPeers, ClientError> {
        self.request_infallible(RequestPeers::new()).await
    }

    /// Sends a message to the peer, but does not expect any response.
    pub async fn send<T>(&self, body: T) -> Result<(), ClientError>
    where
        T: Streamable + ChiaProtocolMessage,
    {
        self.send_raw(Message {
            msg_type: T::msg_type(),
            id: None,
            data: body.to_bytes()?.into(),
        })
        .await?;

        Ok(())
    }

    /// Sends a message to the peer and expects a message that's either a response or a rejection.
    pub async fn request_fallible<T, E, B>(&self, body: B) -> Result<Response<T, E>, ClientError>
    where
        T: Streamable + ChiaProtocolMessage,
        E: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage,
    {
        let message = self.request_raw(body).await?;
        if message.msg_type != T::msg_type() && message.msg_type != E::msg_type() {
            return Err(ClientError::InvalidResponse(
                vec![T::msg_type(), E::msg_type()],
                message.msg_type,
            ));
        }
        if message.msg_type == T::msg_type() {
            Ok(Ok(T::from_bytes(&message.data)?))
        } else {
            Ok(Err(E::from_bytes(&message.data)?))
        }
    }

    /// Sends a message to the peer and expects a specific response message.
    pub async fn request_infallible<T, B>(&self, body: B) -> Result<T, ClientError>
    where
        T: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage,
    {
        let message = self.request_raw(body).await?;
        if message.msg_type != T::msg_type() {
            return Err(ClientError::InvalidResponse(
                vec![T::msg_type()],
                message.msg_type,
            ));
        }
        Ok(T::from_bytes(&message.data)?)
    }

    /// Sends a message to the peer and expects any arbitrary protocol message without parsing it.
    ///
    /// If [`PeerOptions::request_timeout`] is set and the response doesn't arrive in time,
    /// this fails with [`ClientError::Timeout`]. A response that arrives later is ignored.
    pub async fn request_raw<T>(&self, body: T) -> Result<Message, ClientError>
    where
        T: Streamable + ChiaProtocolMessage,
    {
        let (sender, mut receiver) = oneshot::channel();

        let Some(id) = self.0.requests.insert(sender).await else {
            return Err(ClientError::ConnectionClosed);
        };

        let request = async {
            self.send_raw(Message {
                msg_type: T::msg_type(),
                id: Some(id),
                data: body.to_bytes()?.into(),
            })
            .await?;

            Ok((&mut receiver).await?)
        };

        let Some(timeout) = self.0.request_timeout else {
            return request.await;
        };

        if let Ok(result) = tokio::time::timeout(timeout, request).await {
            result
        } else {
            // The receiver is still alive here, so the id can't have been handed out again yet.
            self.0.requests.remove(id).await;
            Err(ClientError::Timeout(timeout))
        }
    }

    async fn send_raw(&self, message: Message) -> Result<(), ClientError> {
        loop {
            if !self
                .0
                .outbound_rate_limiter
                .lock()
                .await
                .handle_message(&message)
            {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            self.0
                .sink
                .lock()
                .await
                .send(message.to_bytes()?.into())
                .await?;

            return Ok(());
        }
    }

    /// Closes the connection. Pending requests fail with [`ClientError::Recv`], new requests fail
    /// with [`ClientError::ConnectionClosed`], and the message receiver ends once the peer
    /// acknowledges the close.
    pub async fn close(&self) -> Result<(), ClientError> {
        self.0.requests.close().await;
        self.0.sink.lock().await.close().await?;
        Ok(())
    }
}

impl Drop for PeerInner {
    fn drop(&mut self) {
        self.inbound_handle.abort();
    }
}

async fn handle_inbound_messages(
    mut stream: Stream,
    sender: mpsc::Sender<Message>,
    requests: &RequestMap,
) -> Result<(), ClientError> {
    use tungstenite::Message::{Binary, Close, Frame, Ping, Pong, Text};

    // Whether unsolicited messages are being dropped, so that the warning is only logged once.
    let mut dropping = false;

    while let Some(message) = stream.next().await {
        let message = message?;

        match message {
            Frame(..) => unreachable!(),
            Close(..) => break,
            Ping(..) | Pong(..) => {}
            Text(text) => {
                warn!("Received unexpected text message: {text}");
            }
            Binary(binary) => {
                let message = Message::from_bytes(&binary)?;

                let Some(id) = message.id else {
                    // Waiting for the receiver here would also hold up the response to every
                    // request behind this message, so drop it instead if the buffer is full.
                    match sender.try_send(message) {
                        Ok(()) => {
                            if dropping {
                                debug!("Message receiver caught up");
                                dropping = false;
                            }
                        }
                        Err(TrySendError::Full(message)) => {
                            if !dropping {
                                warn!(
                                    "Message receiver is full, dropping {:?} message and any others until it's drained",
                                    message.msg_type
                                );
                                dropping = true;
                            }
                        }
                        Err(TrySendError::Closed(_)) => {}
                    }
                    continue;
                };

                let Some(request) = requests.remove(id).await else {
                    // This is most likely the late response to a request that timed out or was
                    // cancelled, so it isn't a reason to drop the connection.
                    debug!(
                        "Received {:?} message with untracked id {id}",
                        message.msg_type
                    );
                    continue;
                };

                request.send(message);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chia_bls::{PublicKey, Signature};
    use chia_protocol::{
        Bytes, ClassgroupElement, Coin, CoinState, Foliage, FoliageBlockData, NewPeakWallet,
        PoolTarget, ProofOfSpace, ProtocolMessageTypes, RewardChainBlock, VDFInfo, VDFProof,
    };
    use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
    use tokio_tungstenite::accept_async;

    use super::*;

    type Server = WebSocketStream<TcpStream>;

    /// Connects a peer to a bare websocket server, which the test drives by hand.
    async fn connect(
        options: PeerOptions,
    ) -> anyhow::Result<(Peer, mpsc::Receiver<Message>, Server)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            anyhow::Ok(accept_async(stream).await?)
        });

        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}")).await?;
        let (peer, receiver) = Peer::from_websocket(ws, options)?;

        Ok((peer, receiver, server.await??))
    }

    async fn next_request(server: &mut Server) -> anyhow::Result<Message> {
        loop {
            let message = server.next().await.expect("connection closed")?;
            if let tungstenite::Message::Binary(binary) = message {
                return Ok(Message::from_bytes(&binary)?);
            }
        }
    }

    async fn send_message<T>(server: &mut Server, id: Option<u16>, body: T) -> anyhow::Result<()>
    where
        T: Streamable + ChiaProtocolMessage,
    {
        let message = Message {
            msg_type: T::msg_type(),
            id,
            data: body.to_bytes()?.into(),
        };
        server.send(message.to_bytes()?.into()).await?;
        Ok(())
    }

    fn new_peak(height: u32) -> NewPeakWallet {
        NewPeakWallet::new(
            Bytes32::new([height.to_be_bytes()[3]; 32]),
            height,
            0,
            height,
        )
    }

    fn children(amount: u64) -> RespondChildren {
        RespondChildren::new(vec![CoinState::new(
            Coin::new(Bytes32::default(), Bytes32::default(), amount),
            None,
            Some(0),
        )])
    }

    fn header_block(height: u32) -> HeaderBlock {
        let vdf = VDFInfo::new(Bytes32::default(), 0, ClassgroupElement::default());
        let proof = VDFProof::new(0, Bytes::default(), false);

        HeaderBlock::new(
            Vec::new(),
            RewardChainBlock::new(
                0,
                height,
                0,
                0,
                Bytes32::default(),
                ProofOfSpace::new(
                    Bytes32::default(),
                    None,
                    None,
                    PublicKey::default(),
                    0,
                    0,
                    0,
                    0,
                    32,
                    Bytes::default(),
                ),
                None,
                Signature::default(),
                vdf.clone(),
                None,
                Signature::default(),
                vdf,
                None,
                None,
                false,
            ),
            None,
            proof.clone(),
            None,
            proof,
            None,
            Foliage::new(
                Bytes32::default(),
                Bytes32::default(),
                FoliageBlockData::new(
                    Bytes32::default(),
                    PoolTarget::new(Bytes32::default(), 0),
                    None,
                    Bytes32::default(),
                    Bytes32::default(),
                ),
                Signature::default(),
                None,
                None,
            ),
            None,
            Bytes::default(),
            None,
        )
    }

    #[tokio::test]
    async fn test_request_timeout() -> anyhow::Result<()> {
        let options = PeerOptions {
            request_timeout: Some(Duration::from_millis(200)),
            ..PeerOptions::default()
        };
        let (peer, _receiver, mut server) = connect(options).await?;

        // The server never answers in time.
        let result = peer.request_children(Bytes32::default()).await;
        assert!(matches!(result, Err(ClientError::Timeout(_))));

        let late = next_request(&mut server).await?;
        assert_eq!(late.msg_type, ProtocolMessageTypes::RequestChildren);

        let server: JoinHandle<anyhow::Result<Server>> = tokio::spawn(async move {
            // The late response must be ignored rather than closing the connection
            // or being mistaken for the response to the next request.
            send_message(&mut server, late.id, children(1)).await?;

            let request = next_request(&mut server).await?;
            assert_ne!(request.id, late.id);
            send_message(&mut server, request.id, children(2)).await?;

            Ok(server)
        });

        let response = peer.request_children(Bytes32::default()).await?;
        assert_eq!(response, children(2));

        server.await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_undrained_messages_dont_block_responses() -> anyhow::Result<()> {
        let (peer, mut receiver, mut server) = connect(PeerOptions::default()).await?;

        let buffer_size = u32::try_from(MESSAGE_BUFFER_SIZE)?;
        let count = buffer_size * 4;

        let server: JoinHandle<anyhow::Result<Server>> = tokio::spawn(async move {
            let request = next_request(&mut server).await?;

            // More unsolicited messages than the buffer holds, none of which are read.
            for height in 0..count {
                send_message(&mut server, None, new_peak(height)).await?;
            }

            send_message(&mut server, request.id, children(1)).await?;

            Ok(server)
        });

        let response = timeout(
            Duration::from_secs(10),
            peer.request_children(Bytes32::default()),
        )
        .await
        .expect("the response was blocked by undrained messages")?;
        assert_eq!(response, children(1));

        let mut server = server.await??;

        // The oldest messages are kept, and the rest are dropped.
        for height in 0..buffer_size {
            let message = receiver.try_recv()?;
            assert_eq!(NewPeakWallet::from_bytes(&message.data)?, new_peak(height));
        }
        assert!(receiver.try_recv().is_err());

        // Once the receiver is drained, new messages are delivered again.
        send_message(&mut server, None, new_peak(count)).await?;
        let message = timeout(Duration::from_secs(10), receiver.recv())
            .await?
            .expect("missing message");
        assert_eq!(NewPeakWallet::from_bytes(&message.data)?, new_peak(count));

        Ok(())
    }

    #[tokio::test]
    async fn test_pending_request_fails_on_disconnect() -> anyhow::Result<()> {
        let options = PeerOptions {
            request_timeout: None,
            ..PeerOptions::default()
        };
        let (peer, mut receiver, mut server) = connect(options).await?;

        let server = tokio::spawn(async move {
            next_request(&mut server).await?;
            drop(server);
            anyhow::Ok(())
        });

        let result = timeout(
            Duration::from_secs(10),
            peer.request_children(Bytes32::default()),
        )
        .await
        .expect("the pending request was never failed");
        assert!(matches!(result, Err(ClientError::Recv(_))));

        server.await??;

        let result = peer.request_children(Bytes32::default()).await;
        assert!(matches!(result, Err(ClientError::ConnectionClosed)));
        assert!(receiver.recv().await.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_close() -> anyhow::Result<()> {
        let (peer, mut receiver, mut server) = connect(PeerOptions::default()).await?;

        // The server just completes the close handshake.
        let server = tokio::spawn(async move { while server.next().await.is_some() {} });

        peer.close().await?;

        let result = peer.request_children(Bytes32::default()).await;
        assert!(matches!(result, Err(ClientError::ConnectionClosed)));

        let message = timeout(Duration::from_secs(10), receiver.recv()).await?;
        assert!(message.is_none());

        server.await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_request_block_header() -> anyhow::Result<()> {
        let (peer, _receiver, mut server) = connect(PeerOptions::default()).await?;

        let server = tokio::spawn(async move {
            let request = next_request(&mut server).await?;
            assert_eq!(request.msg_type, ProtocolMessageTypes::RequestBlockHeader);
            let body = RequestBlockHeader::from_bytes(&request.data)?;
            send_message(
                &mut server,
                request.id,
                RespondBlockHeader::new(header_block(body.height)),
            )
            .await?;

            let request = next_request(&mut server).await?;
            let body = RequestBlockHeader::from_bytes(&request.data)?;
            send_message(
                &mut server,
                request.id,
                RejectHeaderRequest::new(body.height),
            )
            .await?;

            anyhow::Ok(server)
        });

        let header_block = peer.request_block_header(42).await?.unwrap();
        assert_eq!(header_block.reward_chain_block.height, 42);

        let rejection = peer.request_block_header(1_000_000).await?.unwrap_err();
        assert_eq!(rejection.height, 1_000_000);

        server.await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_request_block_headers() -> anyhow::Result<()> {
        let (peer, _receiver, mut server) = connect(PeerOptions::default()).await?;

        let server = tokio::spawn(async move {
            let request = next_request(&mut server).await?;
            assert_eq!(request.msg_type, ProtocolMessageTypes::RequestBlockHeaders);
            let body = RequestBlockHeaders::from_bytes(&request.data)?;
            assert!(!body.return_filter);
            send_message(
                &mut server,
                request.id,
                RespondBlockHeaders::new(
                    body.start_height,
                    body.end_height,
                    (body.start_height..=body.end_height)
                        .map(header_block)
                        .collect(),
                ),
            )
            .await?;

            let request = next_request(&mut server).await?;
            let body = RequestBlockHeaders::from_bytes(&request.data)?;
            send_message(
                &mut server,
                request.id,
                RejectBlockHeaders::new(body.start_height, body.end_height),
            )
            .await?;

            anyhow::Ok(server)
        });

        let response = peer.request_block_headers(10, 12, false).await?.unwrap();
        assert_eq!(response.start_height, 10);
        assert_eq!(response.end_height, 12);
        assert_eq!(
            response
                .header_blocks
                .iter()
                .map(|block| block.reward_chain_block.height)
                .collect::<Vec<_>>(),
            vec![10, 11, 12]
        );

        let rejection = peer
            .request_block_headers(0, 1000, false)
            .await?
            .unwrap_err();
        assert_eq!(rejection.start_height, 0);
        assert_eq!(rejection.end_height, 1000);

        server.await??;

        Ok(())
    }
}
