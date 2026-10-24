use std::{sync::Arc, time::Duration};

use bindy::Result;
use chia_protocol::{
    Bytes32, CoinState, CoinStateUpdate, HeaderBlock, Message, NewPeakWallet, ProtocolMessageTypes,
    PuzzleSolutionResponse, RespondBlockHeaders, RespondCoinState, RespondPuzzleState, SpendBundle,
    TransactionAck,
};
use chia_sdk_client::{
    Connector as SdkConnector, Peer as SdkPeer, PeerOptions as SdkPeerOptions, connect_peer,
    create_native_tls_connector, load_ssl_cert,
};
use chia_ssl::ChiaCertificate;
use chia_traits::Streamable;
use tokio::sync::{Mutex, mpsc::Receiver};

#[derive(Clone)]
pub struct Certificate {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Certificate {
    pub fn load(cert_path: String, key_path: String) -> Result<Self> {
        let cert = load_ssl_cert(&cert_path, &key_path)?;
        Ok(Self {
            cert_pem: cert.cert_pem,
            key_pem: cert.key_pem,
        })
    }

    pub fn generate() -> Result<Self> {
        let cert = ChiaCertificate::generate()?;
        Ok(Self {
            cert_pem: cert.cert_pem,
            key_pem: cert.key_pem,
        })
    }
}

#[derive(Clone)]
pub struct Connector(SdkConnector);

impl Connector {
    pub fn new(cert: Certificate) -> Result<Self> {
        let connector = create_native_tls_connector(&ChiaCertificate {
            cert_pem: cert.cert_pem,
            key_pem: cert.key_pem,
        })?;
        Ok(Self(connector))
    }
}

#[derive(Clone)]
pub struct PeerOptions {
    pub rate_limit_factor: f64,
    pub request_timeout_ms: Option<u32>,
}

impl PeerOptions {
    pub fn new() -> Result<Self> {
        let options = SdkPeerOptions::default();
        Ok(Self {
            rate_limit_factor: options.rate_limit_factor,
            request_timeout_ms: options
                .request_timeout
                .map(|timeout| timeout.as_millis().try_into().unwrap_or(u32::MAX)),
        })
    }
}

impl From<PeerOptions> for SdkPeerOptions {
    fn from(value: PeerOptions) -> Self {
        Self {
            rate_limit_factor: value.rate_limit_factor,
            request_timeout: value
                .request_timeout_ms
                .map(|ms| Duration::from_millis(ms.into())),
        }
    }
}

#[derive(Clone)]
pub struct CoinStateFilters {
    pub include_spent: bool,
    pub include_unspent: bool,
    pub include_hinted: bool,
    pub min_amount: u64,
}

impl From<CoinStateFilters> for chia_protocol::CoinStateFilters {
    fn from(value: CoinStateFilters) -> Self {
        Self {
            include_spent: value.include_spent,
            include_unspent: value.include_unspent,
            include_hinted: value.include_hinted,
            min_amount: value.min_amount,
        }
    }
}

#[derive(Clone)]
pub struct Peer(SdkPeer, Arc<Mutex<Receiver<Message>>>);

impl Peer {
    pub async fn connect(
        network_id: String,
        socket_addr: String,
        connector: Connector,
        options: PeerOptions,
    ) -> Result<Self> {
        let (peer, receiver) = connect_peer(
            network_id,
            connector.0.clone(),
            socket_addr.parse()?,
            options.into(),
        )
        .await?;

        Ok(Self(peer, Arc::new(Mutex::new(receiver))))
    }

    pub async fn request_coin_state(
        &self,
        coin_ids: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
        subscribe: bool,
    ) -> Result<RespondCoinState> {
        self.0
            .request_coin_state(coin_ids, previous_height, header_hash, subscribe)
            .await?
            .map_err(bindy::Error::RejectCoinState)
    }

    pub async fn request_puzzle_state(
        &self,
        puzzle_hashes: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
        filters: CoinStateFilters,
        subscribe: bool,
    ) -> Result<RespondPuzzleState> {
        self.0
            .request_puzzle_state(
                puzzle_hashes,
                previous_height,
                header_hash,
                filters.into(),
                subscribe,
            )
            .await?
            .map_err(bindy::Error::RejectPuzzleState)
    }

    pub async fn request_puzzle_and_solution(
        &self,
        coin_id: Bytes32,
        height: u32,
    ) -> Result<PuzzleSolutionResponse> {
        self.0
            .request_puzzle_and_solution(coin_id, height)
            .await?
            .map_err(bindy::Error::RejectPuzzleSolution)
    }

    pub async fn request_children(&self, coin_id: Bytes32) -> Result<Vec<CoinState>> {
        Ok(self.0.request_children(coin_id).await?.coin_states)
    }

    pub async fn request_block_header(&self, height: u32) -> Result<HeaderBlock> {
        self.0
            .request_block_header(height)
            .await?
            .map_err(bindy::Error::RejectHeaderRequest)
    }

    pub async fn request_block_headers(
        &self,
        start_height: u32,
        end_height: u32,
        return_filter: bool,
    ) -> Result<RespondBlockHeaders> {
        self.0
            .request_block_headers(start_height, end_height, return_filter)
            .await?
            .map_err(bindy::Error::RejectBlockHeaders)
    }

    pub async fn send_transaction(&self, spend_bundle: SpendBundle) -> Result<TransactionAck> {
        Ok(self.0.send_transaction(spend_bundle).await?)
    }

    pub async fn remove_coin_subscriptions(
        &self,
        coin_ids: Option<Vec<Bytes32>>,
    ) -> Result<Vec<Bytes32>> {
        Ok(self.0.remove_coin_subscriptions(coin_ids).await?.coin_ids)
    }

    pub async fn remove_puzzle_subscriptions(
        &self,
        puzzle_hashes: Option<Vec<Bytes32>>,
    ) -> Result<Vec<Bytes32>> {
        Ok(self
            .0
            .remove_puzzle_subscriptions(puzzle_hashes)
            .await?
            .puzzle_hashes)
    }

    pub async fn next(&self) -> Result<Option<Event>> {
        let mut receiver = self.1.lock().await;

        while let Some(message) = receiver.recv().await {
            match message.msg_type {
                ProtocolMessageTypes::NewPeakWallet => {
                    return Ok(Some(Event {
                        new_peak_wallet: Some(NewPeakWallet::from_bytes(&message.data)?),
                        coin_state_update: None,
                    }));
                }
                ProtocolMessageTypes::CoinStateUpdate => {
                    return Ok(Some(Event {
                        new_peak_wallet: None,
                        coin_state_update: Some(CoinStateUpdate::from_bytes(&message.data)?),
                    }));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    pub async fn close(&self) -> Result<()> {
        Ok(self.0.close().await?)
    }
}

#[derive(Clone)]
pub struct Event {
    pub new_peak_wallet: Option<NewPeakWallet>,
    pub coin_state_update: Option<CoinStateUpdate>,
}

pub trait RespondCoinStateExt {}

pub trait RespondPuzzleStateExt {}

pub trait PuzzleSolutionResponseExt {}

pub trait CoinStateUpdateExt {}

pub trait NewPeakWalletExt {}
