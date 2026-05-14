#![forbid(unsafe_code)]

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray},
};
use aes_gcm::{Aes128Gcm, Nonce, aead::Payload};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use native_tls::{Identity, TlsConnector};
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, lookup_host},
    sync::Semaphore,
    time::timeout,
};
use tracing::{debug, info};
use uuid::Uuid;
use xrs_common::{Destination, DestinationHost, Network, SessionContext};
use xrs_config::{InboundConfig, InboundProtocol, OutboundConfig, OutboundProtocol, RootConfig};
use xrs_observability::TrafficCounters;
use xrs_router::{Router, RoutingDomainStrategy};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_MESSAGE_SIZE: usize = 4096;
const MAX_CONNECTIONS_PER_INBOUND: usize = 1024;
const SHADOWSOCKS_METHOD: &str = "chacha20-ietf-poly1305";
const SHADOWSOCKS_KEY_LEN: usize = 32;
const SHADOWSOCKS_SALT_LEN: usize = 32;
const SHADOWSOCKS_NONCE_LEN: usize = 12;
const SHADOWSOCKS_TAG_LEN: usize = 16;
const SHADOWSOCKS_MAX_CHUNK: usize = 0x3fff;
const VMESS_AEAD_AUTH_ID_ENCRYPTION: &[u8] = b"AES Auth ID Encryption";
const VMESS_AEAD_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_AEAD_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_AEAD_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_AEAD_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const VMESS_AEAD_RESP_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const VMESS_AEAD_RESP_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const VMESS_AEAD_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const VMESS_AEAD_RESP_IV: &[u8] = b"AEAD Resp Header IV";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const VMESS_SECURITY_NONE: u8 = 5;
const VMESS_OPTION_CHUNK_STREAM: u8 = 0x01;
const VMESS_OPTION_CHUNK_MASKING: u8 = 0x04;
const VMESS_MAX_CHUNK: usize = 0x3fff;
const VMESS_AUTH_ID_TTL: i64 = 120;
const VMESS_REPLAY_CACHE_MAX: usize = 4096;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Router(#[from] xrs_router::RouterError),
    #[error("outbound tag {0} is not configured")]
    MissingOutbound(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("operation timed out")]
    Timeout,
    #[error("connection limit reached")]
    ConnectionLimit,
    #[error("SOCKS5 client used unsupported version {0}")]
    UnsupportedSocksVersion(u8),
    #[error("SOCKS5 request command {0} is not supported")]
    UnsupportedSocksCommand(u8),
    #[error("SOCKS5 UDP packet is malformed")]
    MalformedSocksUdpPacket,
    #[error("SOCKS5 UDP fragmentation is not supported")]
    UnsupportedSocksUdpFragment,
    #[error("SOCKS5 UDP routing target {0} is not supported")]
    UnsupportedSocksUdpOutbound(String),
    #[error("SOCKS5 address type {0} is not supported")]
    UnsupportedSocksAddress(u8),
    #[error("SOCKS5 client did not offer an acceptable authentication method")]
    UnsupportedSocksMethod,
    #[error("proxy authentication failed")]
    ProxyAuthenticationFailed,
    #[error("HTTP request is not a CONNECT request")]
    UnsupportedHttpRequest,
    #[error("HTTP CONNECT target is missing or invalid")]
    InvalidHttpTarget,
    #[error("dokodemo-door inbound requires settings.address and settings.port")]
    InvalidDokodemoSettings,
    #[error("HTTP CONNECT header exceeded 8192 bytes")]
    HttpHeaderTooLarge,
    #[error("DNS message length is invalid")]
    InvalidDnsMessageLength,
    #[error("DNS message exceeded 4096 bytes")]
    DnsMessageTooLarge,
    #[error("proxy outbound is missing server settings")]
    MissingProxyServer,
    #[error("SOCKS5 upstream returned unexpected response")]
    UnexpectedSocksResponse,
    #[error("HTTP upstream returned non-success CONNECT response")]
    UnexpectedHttpResponse,
    #[error("SOCKS5 domain target is too long")]
    SocksDomainTooLong,
    #[error("trojan inbound is missing client settings")]
    MissingTrojanClients,
    #[error("trojan password is invalid")]
    InvalidTrojanPassword,
    #[error("trojan request command {0} is not supported")]
    UnsupportedTrojanCommand(u8),
    #[error("trojan address type {0} is not supported")]
    UnsupportedTrojanAddress(u8),
    #[error("trojan request is malformed")]
    MalformedTrojanRequest,
    #[error("vless inbound is missing client settings")]
    MissingVlessClients,
    #[error("vless client id is invalid")]
    InvalidVlessClient,
    #[error("VLESS version {0} is not supported")]
    UnsupportedVlessVersion(u8),
    #[error("VLESS request command {0} is not supported")]
    UnsupportedVlessCommand(u8),
    #[error("VLESS address type {0} is not supported")]
    UnsupportedVlessAddress(u8),
    #[error("shadowsocks method is not supported")]
    UnsupportedShadowsocksMethod,
    #[error("shadowsocks authentication or decryption failed")]
    ShadowsocksDecryptFailed,
    #[error("shadowsocks address is malformed")]
    MalformedShadowsocksAddress,
    #[error("shadowsocks settings are missing")]
    MissingShadowsocksSettings,
    #[error("vmess inbound is missing client settings")]
    MissingVmessClients,
    #[error("vmess client id is invalid")]
    InvalidVmessClient,
    #[error("vmess auth id is invalid")]
    InvalidVmessAuthId,
    #[error("vmess header authentication failed")]
    VmessDecryptFailed,
    #[error("VMess request command {0} is not supported")]
    UnsupportedVmessCommand(u8),
    #[error("VMess address type {0} is not supported")]
    UnsupportedVmessAddress(u8),
    #[error("VMess body security {0} is not supported")]
    UnsupportedVmessSecurity(u8),
    #[error("vmess request is malformed")]
    MalformedVmessRequest,
    #[error("vmess settings are missing")]
    MissingVmessSettings,
    #[error("vmess auth id was replayed")]
    VmessReplay,
    #[error("TLS outbound to IP destination requires tlsSettings.serverName")]
    MissingTlsServerName,
    #[error("TLS error: {0}")]
    Tls(#[from] native_tls::Error),
    #[error("TLS inbound requires tlsSettings.certificates[0].certificateFile and keyFile")]
    MissingTlsIdentity,
    #[error("TLS freedom outbound does not support encrypted inbound relay")]
    UnsupportedTlsEncryptedRelay,
}

#[derive(Default)]
struct VmessReplayCache {
    entries: Mutex<HashMap<[u8; 16], i64>>,
}

impl VmessReplayCache {
    fn check_and_insert(&self, auth_id: [u8; 16], now: i64) -> Result<(), CoreError> {
        let mut entries = self
            .entries
            .lock()
            .expect("replay cache mutex not poisoned");
        entries.retain(|_, timestamp| now - *timestamp <= VMESS_AUTH_ID_TTL);
        if entries.contains_key(&auth_id) {
            return Err(CoreError::VmessReplay);
        }
        if entries.len() >= VMESS_REPLAY_CACHE_MAX
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, timestamp)| **timestamp)
                .map(|(auth_id, _)| *auth_id)
        {
            entries.remove(&oldest);
        }
        entries.insert(auth_id, now);
        Ok(())
    }
}

struct AcceptedClient {
    stream: TcpStream,
    source_ip: IpAddr,
    source_port: u16,
}

struct AcceptedInbound {
    destination: Destination,
    remote_prefix: Vec<u8>,
    client_prefix: Vec<u8>,
    shadowsocks: Option<ShadowsocksSession>,
    vmess: Option<VmessSession>,
    socks_udp: Option<SocksUdpAssociate>,
}

impl AcceptedInbound {
    fn new(destination: Destination) -> Self {
        Self {
            destination,
            remote_prefix: Vec::new(),
            client_prefix: Vec::new(),
            shadowsocks: None,
            vmess: None,
            socks_udp: None,
        }
    }
}

#[derive(Debug)]
pub struct Runtime {
    config: RootConfig,
    router: Router,
    counters: Arc<TrafficCounters>,
}

impl Runtime {
    pub fn new(config: RootConfig) -> Result<Self, CoreError> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            router: Router::from_config(&config)?,
            config,
            counters: Arc::new(TrafficCounters::default()),
        })
    }

    pub async fn run(self) -> Result<(), CoreError> {
        let outbounds = Arc::new(
            self.config
                .outbounds
                .iter()
                .map(|outbound| (outbound.tag.clone(), outbound.clone()))
                .collect::<HashMap<_, _>>(),
        );
        let router = Arc::new(self.router);
        let vmess_replay = Arc::new(VmessReplayCache::default());
        let mut listeners = Vec::with_capacity(self.config.inbounds.len());

        for inbound in self.config.inbounds.clone() {
            if shadowsocks_udp_enabled(&inbound) {
                let socket = bind_udp_inbound(&inbound).await?;
                let inbound = inbound.clone();
                let router = Arc::clone(&router);
                let outbounds = Arc::clone(&outbounds);
                let counters = Arc::clone(&self.counters);
                tokio::spawn(async move {
                    if let Err(error) =
                        run_shadowsocks_udp_inbound(inbound, socket, router, outbounds, counters)
                            .await
                    {
                        tracing::error!(%error, "shadowsocks UDP inbound stopped");
                    }
                });
            }
            if inbound_tcp_enabled(&inbound) {
                listeners.push(bind_inbound(inbound).await?);
            }
        }

        for (inbound, listener) in listeners {
            let router = Arc::clone(&router);
            let outbounds = Arc::clone(&outbounds);
            let counters = Arc::clone(&self.counters);
            let vmess_replay = Arc::clone(&vmess_replay);
            tokio::spawn(async move {
                if let Err(error) =
                    run_inbound(inbound, listener, router, outbounds, counters, vmess_replay).await
                {
                    tracing::error!(%error, "inbound stopped");
                }
            });
        }

        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

async fn bind_inbound(inbound: InboundConfig) -> Result<(InboundConfig, TcpListener), CoreError> {
    let address = inbound_socket_addr(&inbound);
    let listener = TcpListener::bind(address).await?;
    info!(tag = inbound.tag, %address, protocol = ?inbound.protocol, "listening");
    Ok((inbound, listener))
}

async fn bind_udp_inbound(inbound: &InboundConfig) -> Result<UdpSocket, CoreError> {
    let address = inbound_socket_addr(inbound);
    let socket = UdpSocket::bind(address).await?;
    info!(tag = inbound.tag, %address, protocol = ?inbound.protocol, "listening UDP");
    Ok(socket)
}

fn inbound_socket_addr(inbound: &InboundConfig) -> SocketAddr {
    let listen = inbound
        .listen
        .unwrap_or_else(|| "127.0.0.1".parse().expect("valid loopback"));
    SocketAddr::new(listen, inbound.port)
}

fn shadowsocks_udp_enabled(inbound: &InboundConfig) -> bool {
    inbound.protocol == InboundProtocol::Shadowsocks && inbound_network_contains(inbound, "udp")
}

fn inbound_tcp_enabled(inbound: &InboundConfig) -> bool {
    inbound.protocol != InboundProtocol::Shadowsocks || inbound_network_contains(inbound, "tcp")
}

fn inbound_network_contains(inbound: &InboundConfig, expected: &str) -> bool {
    inbound
        .settings
        .as_ref()
        .and_then(|settings| settings.network.as_deref())
        .map_or(expected == "tcp", |network| {
            network.split(',').any(|part| part.trim() == expected)
        })
}

async fn run_inbound(
    inbound: InboundConfig,
    listener: TcpListener,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    counters: Arc<TrafficCounters>,
    vmess_replay: Arc<VmessReplayCache>,
) -> Result<(), CoreError> {
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_INBOUND));
    let tls_acceptor = inbound_tls_acceptor(&inbound)?;

    loop {
        let (mut client, peer) = listener.accept().await?;
        debug!(%peer, tag = inbound.tag, "accepted connection");
        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                client.shutdown().await?;
                tracing::debug!(%peer, tag = inbound.tag, "connection limit reached");
                continue;
            }
        };
        let inbound = inbound.clone();
        let router = Arc::clone(&router);
        let outbounds = Arc::clone(&outbounds);
        let counters = Arc::clone(&counters);
        let vmess_replay = Arc::clone(&vmess_replay);
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_client(
                AcceptedClient {
                    stream: client,
                    source_ip: peer.ip(),
                    source_port: peer.port(),
                },
                tls_acceptor,
                inbound,
                router,
                outbounds,
                counters,
                vmess_replay,
            )
            .await
            {
                tracing::debug!(%error, "connection finished with error");
            }
        });
    }
}

async fn pick_tcp_outbound<'a>(
    router: &'a Router,
    session: &SessionContext,
    destination: &Destination,
) -> Result<&'a str, CoreError> {
    if let Some(outbound) = router.pick_rule_outbound(session) {
        return Ok(outbound);
    }
    if !matches!(session.destination.host, DestinationHost::Domain(_))
        || router.domain_strategy() != RoutingDomainStrategy::IpIfNonMatch
    {
        return Ok(router.default_outbound());
    }

    let resolved_sessions = lookup_host((destination.host.to_string(), destination.port))
        .await?
        .map(|address| SessionContext {
            inbound_tag: session.inbound_tag.clone(),
            destination: Destination {
                host: DestinationHost::Ip(address.ip()),
                port: destination.port,
                network: destination.network,
            },
            source_ip: session.source_ip,
            source_port: session.source_port,
        })
        .collect::<Vec<_>>();

    Ok(router
        .pick_rule_outbound_for_any(&resolved_sessions)
        .unwrap_or(router.default_outbound()))
}

fn inbound_tls_acceptor(
    inbound: &InboundConfig,
) -> Result<Option<tokio_native_tls::TlsAcceptor>, CoreError> {
    if inbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.security.as_deref())
        != Some("tls")
    {
        return Ok(None);
    }
    let certificate = inbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.tls_settings.as_ref())
        .and_then(|settings| settings.certificates.first())
        .ok_or(CoreError::MissingTlsIdentity)?;
    let certificate_file = certificate
        .certificate_file
        .as_ref()
        .ok_or(CoreError::MissingTlsIdentity)?;
    let key_file = certificate
        .key_file
        .as_ref()
        .ok_or(CoreError::MissingTlsIdentity)?;
    let certificate = std::fs::read(certificate_file)?;
    let key = std::fs::read(key_file)?;
    let identity = Identity::from_pkcs8(&certificate, &key)?;
    Ok(Some(tokio_native_tls::TlsAcceptor::from(
        native_tls::TlsAcceptor::new(identity)?,
    )))
}

async fn handle_client(
    accepted_client: AcceptedClient,
    tls_acceptor: Option<tokio_native_tls::TlsAcceptor>,
    inbound: InboundConfig,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    counters: Arc<TrafficCounters>,
    vmess_replay: Arc<VmessReplayCache>,
) -> Result<(), CoreError> {
    let source_ip = accepted_client.source_ip;
    let source_port = accepted_client.source_port;
    let mut client = match tls_acceptor {
        Some(acceptor) => InboundStream::Tls(
            timeout(HANDSHAKE_TIMEOUT, acceptor.accept(accepted_client.stream))
                .await
                .map_err(|_| CoreError::Timeout)??,
        ),
        None => InboundStream::Tcp(accepted_client.stream),
    };
    let accepted = timeout(HANDSHAKE_TIMEOUT, async {
        match inbound.protocol {
            InboundProtocol::Socks => accept_socks5(&mut client, &inbound).await,
            InboundProtocol::Http => accept_http(&mut client, &inbound).await,
            InboundProtocol::DokodemoDoor => {
                dokodemo_destination(&inbound).map(AcceptedInbound::new)
            }
            InboundProtocol::Trojan => accept_trojan(&mut client, &inbound).await,
            InboundProtocol::Vless => accept_vless(&mut client, &inbound).await,
            InboundProtocol::Vmess => accept_vmess(&mut client, &inbound, &vmess_replay).await,
            InboundProtocol::Shadowsocks => accept_shadowsocks(&mut client, &inbound).await,
        }
    })
    .await
    .map_err(|_| CoreError::Timeout)??;
    if let Some(associate) = accepted.socks_udp {
        let allowed_peer_ip = client.peer_addr()?.ip();
        return handle_socks_udp_associate(
            client,
            associate,
            allowed_peer_ip,
            inbound.tag,
            router,
            outbounds,
            counters,
        )
        .await;
    }
    let destination = accepted.destination;
    let session = SessionContext::new(inbound.tag, destination.clone())
        .with_source_ip(source_ip)
        .with_source_port(source_port);
    let outbound_tag = pick_tcp_outbound(&router, &session, &destination).await?;
    let outbound = outbounds
        .get(outbound_tag)
        .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;

    match outbound.protocol {
        OutboundProtocol::Freedom => {
            let connect_destination = freedom_destination(outbound, &destination)?;
            let uses_tls = outbound
                .stream_settings
                .as_ref()
                .and_then(|settings| settings.security.as_deref())
                == Some("tls");
            if let Some(session) = accepted.shadowsocks {
                if uses_tls {
                    return Err(CoreError::UnsupportedTlsEncryptedRelay);
                }
                let mut remote = connect_tcp(&connect_destination).await?;
                write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
                write_client_prefix(&mut client, &accepted.client_prefix).await?;
                relay_shadowsocks_to_plain(client, session, remote, counters).await?;
            } else if let Some(session) = accepted.vmess {
                if uses_tls {
                    return Err(CoreError::UnsupportedTlsEncryptedRelay);
                }
                let mut remote = connect_tcp(&connect_destination).await?;
                write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
                write_client_prefix(&mut client, &accepted.client_prefix).await?;
                relay_vmess_to_plain(client, session, remote, counters).await?;
            } else {
                let mut remote = connect_freedom(outbound, &connect_destination).await?;
                write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
                write_client_prefix(&mut client, &accepted.client_prefix).await?;
                relay(client, remote, counters).await?;
            }
        }
        OutboundProtocol::Blackhole => {
            handle_blackhole_outbound(&mut client, outbound).await?;
        }
        OutboundProtocol::Dns => {
            handle_dns_outbound(client, outbound, counters).await?;
        }
        OutboundProtocol::Socks => {
            let mut remote = connect_proxy_stream(outbound).await?;
            timeout(
                HANDSHAKE_TIMEOUT,
                connect_socks_upstream(&mut remote, outbound_server(outbound)?, &destination),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
            write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
            write_client_prefix(&mut client, &accepted.client_prefix).await?;
            if let Some(session) = accepted.shadowsocks {
                relay_shadowsocks_to_plain(client, session, remote, counters).await?;
            } else if let Some(session) = accepted.vmess {
                relay_vmess_to_plain(client, session, remote, counters).await?;
            } else {
                relay(client, remote, counters).await?;
            }
        }
        OutboundProtocol::Http => {
            let mut remote = connect_proxy_stream(outbound).await?;
            timeout(
                HANDSHAKE_TIMEOUT,
                connect_http_upstream(&mut remote, outbound_server(outbound)?, &destination),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
            write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
            write_client_prefix(&mut client, &accepted.client_prefix).await?;
            if let Some(session) = accepted.shadowsocks {
                relay_shadowsocks_to_plain(client, session, remote, counters).await?;
            } else if let Some(session) = accepted.vmess {
                relay_vmess_to_plain(client, session, remote, counters).await?;
            } else {
                relay(client, remote, counters).await?;
            }
        }
        OutboundProtocol::Shadowsocks => {
            let (mut remote, outbound_session) =
                connect_shadowsocks_upstream(outbound, &destination).await?;
            write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
            write_client_prefix(&mut client, &accepted.client_prefix).await?;
            if let Some(inbound_session) = accepted.shadowsocks {
                relay_shadowsocks_to_shadowsocks(
                    client,
                    inbound_session,
                    remote,
                    outbound_session,
                    counters,
                )
                .await?;
            } else {
                relay_plain_to_shadowsocks(client, remote, outbound_session, counters).await?;
            }
        }
        OutboundProtocol::Vmess => {
            let (mut remote, outbound_session) =
                connect_vmess_upstream(outbound, &destination).await?;
            write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
            write_client_prefix(&mut client, &accepted.client_prefix).await?;
            if let Some(inbound_session) = accepted.vmess {
                relay_vmess_to_vmess(client, inbound_session, remote, outbound_session, counters)
                    .await?;
            } else {
                relay_plain_to_vmess(client, remote, outbound_session, counters).await?;
            }
        }
    }

    Ok(())
}

fn freedom_destination(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<Destination, CoreError> {
    if let Some(redirect) = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.redirect.as_deref())
    {
        let (host, port) = parse_redirect_target(redirect)?;
        return Ok(Destination::tcp(host, port));
    }
    Ok(destination.clone())
}

fn parse_redirect_target(value: &str) -> Result<(DestinationHost, u16), CoreError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid freedom redirect"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let host = DestinationHost::parse(host)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok((host, port))
}

async fn handle_blackhole_outbound<S>(
    client: &mut S,
    outbound: &OutboundConfig,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    if outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.response.as_ref())
        .is_some_and(|response| response.kind == "http")
    {
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
    }
    client.shutdown().await?;
    Ok(())
}

async fn handle_socks_udp_associate(
    mut client: InboundStream,
    associate: SocksUdpAssociate,
    allowed_peer_ip: IpAddr,
    inbound_tag: String,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError> {
    let mut tcp_probe = [0_u8; 1];
    let mut packet = vec![0_u8; 65535];
    loop {
        tokio::select! {
            result = client.read(&mut tcp_probe) => {
                if result? == 0 {
                    return Ok(());
                }
            }
            result = associate.socket.recv_from(&mut packet) => {
                let (length, peer) = result?;
                if peer.ip() != allowed_peer_ip {
                    continue;
                }
                let parsed = parse_socks_udp_packet(&packet[..length])?;
                let session = SessionContext::new(inbound_tag.clone(), parsed.destination.clone())
                    .with_source_ip(peer.ip())
                    .with_source_port(peer.port());
                let outbound_tag = router.pick_outbound(&session);
                let outbound = outbounds
                    .get(outbound_tag)
                    .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
                let response = send_socks_udp_payload(outbound, &parsed.destination, &parsed.payload).await?;
                let wrapped = encode_socks_udp_packet(&response.destination, &response.payload)?;
                associate.socket.send_to(&wrapped, peer).await?;
                counters.add_uplink(parsed.payload.len() as u64);
                counters.add_downlink(response.payload.len() as u64);
            }
        }
    }
}

async fn run_shadowsocks_udp_inbound(
    inbound: InboundConfig,
    socket: UdpSocket,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError> {
    let password = inbound
        .settings
        .as_ref()
        .and_then(|settings| settings.password.as_deref())
        .filter(|password| !password.is_empty())
        .ok_or(CoreError::MissingShadowsocksSettings)?;
    let key = shadowsocks_password_key(password);
    let socket = Arc::new(socket);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_INBOUND));
    let mut packet = vec![0_u8; 65535];
    loop {
        let (length, peer) = socket.recv_from(&mut packet).await?;
        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            tracing::debug!(%peer, tag = inbound.tag, "shadowsocks UDP packet dropped by concurrency limit");
            continue;
        };
        let packet = packet[..length].to_vec();
        let context = ShadowsocksUdpInboundContext {
            key,
            inbound_tag: inbound.tag.clone(),
            socket: Arc::clone(&socket),
            router: Arc::clone(&router),
            outbounds: Arc::clone(&outbounds),
            counters: Arc::clone(&counters),
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_shadowsocks_udp_packet(context, peer, packet).await {
                tracing::debug!(%error, %peer, "shadowsocks UDP packet dropped");
            }
        });
    }
}

struct ShadowsocksUdpInboundContext {
    key: [u8; SHADOWSOCKS_KEY_LEN],
    inbound_tag: String,
    socket: Arc<UdpSocket>,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    counters: Arc<TrafficCounters>,
}

async fn handle_shadowsocks_udp_packet(
    context: ShadowsocksUdpInboundContext,
    peer: SocketAddr,
    packet: Vec<u8>,
) -> Result<(), CoreError> {
    let (destination, payload) = decrypt_shadowsocks_udp_packet(context.key, &packet)?;
    let session = SessionContext::new(context.inbound_tag, destination.clone())
        .with_source_ip(peer.ip())
        .with_source_port(peer.port());
    let outbound_tag = context.router.pick_outbound(&session);
    let outbound = context
        .outbounds
        .get(outbound_tag)
        .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
    let response = send_socks_udp_payload(outbound, &destination, &payload).await?;
    let wrapped =
        encrypt_shadowsocks_udp_packet(context.key, &response.destination, &response.payload)?;
    context.socket.send_to(&wrapped, peer).await?;
    context.counters.add_uplink(payload.len() as u64);
    context.counters.add_downlink(response.payload.len() as u64);
    Ok(())
}

struct UdpPayloadResponse {
    destination: Destination,
    payload: Vec<u8>,
}

async fn send_socks_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    if outbound_uses_tls(outbound) {
        return Err(CoreError::UnsupportedSocksUdpOutbound(outbound.tag.clone()));
    }
    let target = match outbound.protocol {
        OutboundProtocol::Freedom => (destination.host.to_string(), destination.port),
        OutboundProtocol::Dns => {
            let server = outbound
                .settings
                .as_ref()
                .and_then(|settings| settings.servers.first())
                .ok_or(CoreError::MissingProxyServer)?;
            (server.address.clone(), server.port)
        }
        OutboundProtocol::Shadowsocks => {
            return send_shadowsocks_udp_payload(outbound, destination, payload).await;
        }
        OutboundProtocol::Socks => {
            return send_socks_upstream_udp_payload(outbound, destination, payload).await;
        }
        _ => return Err(CoreError::UnsupportedSocksUdpOutbound(outbound.tag.clone())),
    };
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(target).await?;
    timeout(DNS_TIMEOUT, socket.send(payload))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let mut response = vec![0_u8; 65535];
    let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    response.truncate(length);
    Ok(UdpPayloadResponse {
        destination: destination.clone(),
        payload: response,
    })
}

struct SocksUdpPacket {
    destination: Destination,
    payload: Vec<u8>,
}

fn parse_socks_udp_packet(packet: &[u8]) -> Result<SocksUdpPacket, CoreError> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(CoreError::MalformedSocksUdpPacket);
    }
    if packet[2] != 0 {
        return Err(CoreError::UnsupportedSocksUdpFragment);
    }
    let (host, offset) = parse_socks_udp_host(packet, 3)?;
    if packet.len() < offset + 2 {
        return Err(CoreError::MalformedSocksUdpPacket);
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    Ok(SocksUdpPacket {
        destination: Destination {
            host,
            port,
            network: Network::Udp,
        },
        payload: packet[offset + 2..].to_vec(),
    })
}

fn parse_socks_udp_host(
    packet: &[u8],
    address_type_offset: usize,
) -> Result<(DestinationHost, usize), CoreError> {
    let address_type = *packet
        .get(address_type_offset)
        .ok_or(CoreError::MalformedSocksUdpPacket)?;
    let offset = address_type_offset + 1;
    match address_type {
        0x01 => {
            if packet.len() < offset + 4 {
                return Err(CoreError::MalformedSocksUdpPacket);
            }
            let host = DestinationHost::Ip(IpAddr::from([
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ]));
            Ok((host, offset + 4))
        }
        0x03 => {
            let len = usize::from(
                *packet
                    .get(offset)
                    .ok_or(CoreError::MalformedSocksUdpPacket)?,
            );
            if packet.len() < offset + 1 + len {
                return Err(CoreError::MalformedSocksUdpPacket);
            }
            let domain = str::from_utf8(&packet[offset + 1..offset + 1 + len])
                .map_err(|_| CoreError::MalformedSocksUdpPacket)?;
            let host =
                DestinationHost::parse(domain).map_err(|_| CoreError::MalformedSocksUdpPacket)?;
            Ok((host, offset + 1 + len))
        }
        0x04 => {
            if packet.len() < offset + 16 {
                return Err(CoreError::MalformedSocksUdpPacket);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[offset..offset + 16]);
            Ok((DestinationHost::Ip(IpAddr::from(octets)), offset + 16))
        }
        other => Err(CoreError::UnsupportedSocksAddress(other)),
    }
}

fn encode_socks_udp_packet(
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut packet = vec![0, 0, 0];
    match &destination.host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        DestinationHost::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| CoreError::SocksDomainTooLong)?;
            packet.push(0x03);
            packet.push(len);
            packet.extend_from_slice(domain.as_bytes());
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&destination.port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn outbound_server(outbound: &OutboundConfig) -> Result<&xrs_config::ProxyServerConfig, CoreError> {
    outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.servers.first())
        .ok_or(CoreError::MissingProxyServer)
}

async fn connect_proxy_stream(outbound: &OutboundConfig) -> Result<OutboundStream, CoreError> {
    let server = outbound_server(outbound)?;
    let host =
        DestinationHost::parse(&server.address).map_err(|_| CoreError::MissingProxyServer)?;
    let destination = Destination::tcp(host, server.port);
    connect_outbound_stream(outbound, &destination).await
}

async fn handle_dns_outbound<S>(
    mut client: S,
    outbound: &OutboundConfig,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;

    let mut length_prefix = [0_u8; 2];
    timeout(DNS_TIMEOUT, client.read_exact(&mut length_prefix))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let request_length = u16::from_be_bytes(length_prefix) as usize;
    if request_length == 0 {
        return Err(CoreError::InvalidDnsMessageLength);
    }
    if request_length > MAX_DNS_MESSAGE_SIZE {
        return Err(CoreError::DnsMessageTooLarge);
    }

    let mut request = vec![0_u8; request_length];
    timeout(DNS_TIMEOUT, client.read_exact(&mut request))
        .await
        .map_err(|_| CoreError::Timeout)??;
    counters.add_uplink((request_length + 2) as u64);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket
        .connect((server.address.as_str(), server.port))
        .await?;
    timeout(DNS_TIMEOUT, socket.send(&request))
        .await
        .map_err(|_| CoreError::Timeout)??;

    let mut response = vec![0_u8; MAX_DNS_MESSAGE_SIZE];
    let response_length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    response.truncate(response_length);
    client
        .write_all(&(response_length as u16).to_be_bytes())
        .await?;
    client.write_all(&response).await?;
    counters.add_downlink((response_length + 2) as u64);
    client.shutdown().await?;
    Ok(())
}

async fn connect_socks_upstream<S>(
    stream: &mut S,
    server: &xrs_config::ProxyServerConfig,
    destination: &Destination,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_socks_upstream(stream, server).await?;
    write_socks_upstream_request(stream, 0x01, destination).await?;

    read_socks_upstream_success(stream).await?;
    Ok(())
}

async fn send_socks_upstream_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let server = outbound_server(outbound)?;
    let mut control = connect_proxy_stream(outbound).await?;
    let relay = timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_socks_upstream(&mut control, server).await?;
        let bind_destination = Destination {
            host: DestinationHost::Ip(IpAddr::from([0, 0, 0, 0])),
            port: 0,
            network: Network::Udp,
        };
        write_socks_upstream_request(&mut control, 0x03, &bind_destination).await?;
        read_socks_upstream_success(&mut control).await
    })
    .await
    .map_err(|_| CoreError::Timeout)??;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect((relay.host.to_string(), relay.port)).await?;
    let packet = encode_socks_udp_packet(destination, payload)?;
    timeout(DNS_TIMEOUT, socket.send(&packet))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let mut response = vec![0_u8; 65535];
    let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let parsed = parse_socks_udp_packet(&response[..length])?;
    Ok(UdpPayloadResponse {
        destination: parsed.destination,
        payload: parsed.payload,
    })
}

async fn write_socks_upstream_request<S>(
    stream: &mut S,
    command: u8,
    destination: &Destination,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    let mut request = vec![0x05, command, 0x00];
    match &destination.host {
        DestinationHost::Ip(std::net::IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        DestinationHost::Domain(domain) => {
            let domain_len =
                u8::try_from(domain.len()).map_err(|_| CoreError::SocksDomainTooLong)?;
            request.push(0x03);
            request.push(domain_len);
            request.extend_from_slice(domain.as_bytes());
        }
        DestinationHost::Ip(std::net::IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    stream.write_all(&request).await?;
    Ok(())
}

async fn read_socks_upstream_success<S>(stream: &mut S) -> Result<Destination, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(CoreError::UnexpectedSocksResponse);
    }
    let host = read_socks_host(stream, header[3]).await?;
    let port = read_port(stream).await?;
    Ok(Destination::tcp(host, port))
}

async fn negotiate_socks_upstream<S>(
    stream: &mut S,
    server: &xrs_config::ProxyServerConfig,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let credentials = upstream_credentials(server);
    if credentials.is_some() {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    match (method, credentials) {
        ([0x05, 0x00], None) => Ok(()),
        ([0x05, 0x02], Some((user, password))) => {
            write_socks_password_auth(stream, user, password).await
        }
        _ => Err(CoreError::UnexpectedSocksResponse),
    }
}

fn upstream_credentials(server: &xrs_config::ProxyServerConfig) -> Option<(&str, &str)> {
    Some((server.user.as_deref()?, server.password.as_deref()?))
}

async fn write_socks_password_auth<S>(
    stream: &mut S,
    user: &str,
    password: &str,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user_len = u8::try_from(user.len()).map_err(|_| CoreError::UnexpectedSocksResponse)?;
    let password_len =
        u8::try_from(password.len()).map_err(|_| CoreError::UnexpectedSocksResponse)?;
    stream.write_all(&[0x01, user_len]).await?;
    stream.write_all(user.as_bytes()).await?;
    stream.write_all(&[password_len]).await?;
    stream.write_all(password.as_bytes()).await?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(CoreError::UnexpectedSocksResponse);
    }
    Ok(())
}

async fn connect_http_upstream<S>(
    stream: &mut S,
    server: &xrs_config::ProxyServerConfig,
    destination: &Destination,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = http_connect_target(destination);
    let auth_header = upstream_credentials(server)
        .map(|(user, password)| {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                encode_base64(format!("{user}:{password}").as_bytes())
            )
        })
        .unwrap_or_default();
    stream
        .write_all(
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth_header}\r\n").as_bytes(),
        )
        .await?;

    let mut response = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    let mut complete = false;
    while response.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(CoreError::HttpHeaderTooLarge);
    }
    let response = String::from_utf8_lossy(&response);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(CoreError::UnexpectedHttpResponse)?;
    if !(200..300).contains(&status) {
        return Err(CoreError::UnexpectedHttpResponse);
    }
    Ok(())
}

fn http_connect_target(destination: &Destination) -> String {
    match &destination.host {
        DestinationHost::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]:{}", destination.port),
        host => format!("{host}:{}", destination.port),
    }
}

fn dokodemo_destination(inbound: &InboundConfig) -> Result<Destination, CoreError> {
    let settings = inbound
        .settings
        .as_ref()
        .ok_or(CoreError::InvalidDokodemoSettings)?;
    let address = settings
        .address
        .as_deref()
        .ok_or(CoreError::InvalidDokodemoSettings)?;
    let port = settings.port.ok_or(CoreError::InvalidDokodemoSettings)?;
    let host = DestinationHost::parse(address)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(Destination::tcp(host, port))
}

async fn accept_trojan<S>(
    stream: &mut S,
    inbound: &InboundConfig,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + Unpin,
{
    let settings = inbound
        .settings
        .as_ref()
        .ok_or(CoreError::MissingTrojanClients)?;
    if settings.clients.is_empty() {
        return Err(CoreError::MissingTrojanClients);
    }

    let mut password = [0_u8; 56];
    stream.read_exact(&mut password).await?;
    read_trojan_crlf(stream).await?;
    if !settings.clients.iter().any(|client| {
        client
            .password
            .as_deref()
            .is_some_and(|client_password| password == trojan_password_hash(client_password))
    }) {
        return Err(CoreError::InvalidTrojanPassword);
    }

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    if command[0] != 0x01 {
        return Err(CoreError::UnsupportedTrojanCommand(command[0]));
    }

    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    let host = read_socks_host(stream, address_type[0])
        .await
        .map_err(|error| match error {
            CoreError::UnsupportedSocksAddress(address_type) => {
                CoreError::UnsupportedTrojanAddress(address_type)
            }
            error => error,
        })?;
    let port = read_port(stream).await?;
    read_trojan_crlf(stream).await?;

    Ok(AcceptedInbound::new(Destination::tcp(host, port)))
}

fn trojan_password_hash(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut hash = [0_u8; 56];
    for (index, byte) in digest.iter().enumerate() {
        let offset = index * 2;
        hash[offset] = hex_digit(byte >> 4);
        hash[offset + 1] = hex_digit(byte & 0x0f);
    }
    hash
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + (value - 10),
        _ => unreachable!("nibble is always in range"),
    }
}

async fn read_trojan_crlf<S>(stream: &mut S) -> Result<(), CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut crlf = [0_u8; 2];
    stream.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(CoreError::MalformedTrojanRequest);
    }
    Ok(())
}

async fn accept_vless<S>(
    stream: &mut S,
    inbound: &InboundConfig,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + Unpin,
{
    let settings = inbound
        .settings
        .as_ref()
        .ok_or(CoreError::MissingVlessClients)?;
    if settings.clients.is_empty() {
        return Err(CoreError::MissingVlessClients);
    }

    let mut version = [0_u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 0 {
        return Err(CoreError::UnsupportedVlessVersion(version[0]));
    }

    let mut client_id = [0_u8; 16];
    stream.read_exact(&mut client_id).await?;
    if !settings.clients.iter().any(|client| {
        client
            .id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .is_some_and(|id| id.as_bytes() == &client_id)
    }) {
        return Err(CoreError::InvalidVlessClient);
    }

    let mut option_length = [0_u8; 1];
    stream.read_exact(&mut option_length).await?;
    let mut options = vec![0_u8; usize::from(option_length[0])];
    stream.read_exact(&mut options).await?;

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    if command[0] != 0x01 {
        return Err(CoreError::UnsupportedVlessCommand(command[0]));
    }

    let port = read_port(stream).await?;
    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    let host = read_vless_host(stream, address_type[0]).await?;

    Ok(AcceptedInbound {
        destination: Destination::tcp(host, port),
        remote_prefix: Vec::new(),
        client_prefix: vec![version[0], 0],
        shadowsocks: None,
        vmess: None,
        socks_udp: None,
    })
}

async fn read_vless_host<S>(stream: &mut S, address_type: u8) -> Result<DestinationHost, CoreError>
where
    S: AsyncRead + Unpin,
{
    match address_type {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Ok(DestinationHost::Ip(octets.into()))
        }
        0x02 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8_lossy(&domain);
            DestinationHost::parse(&domain)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error).into())
        }
        0x03 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            Ok(DestinationHost::Ip(octets.into()))
        }
        other => Err(CoreError::UnsupportedVlessAddress(other)),
    }
}

struct SocksUdpAssociate {
    socket: UdpSocket,
}

struct SocksRequest {
    command: u8,
    destination: Destination,
}

#[derive(Clone)]
struct VmessSession {
    reader: VmessReader,
    writer: VmessWriter,
    response_auth: u8,
}

#[derive(Clone)]
struct VmessReader {
    iv: [u8; 16],
    nonce: u32,
    masked: bool,
}

impl VmessReader {
    async fn read_chunk<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let mut len_bytes = [0_u8; 2];
        match stream.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if self.masked {
            vmess_mask_length(&mut len_bytes, &self.iv, self.nonce);
        }
        self.nonce = self.nonce.wrapping_add(1);
        let len = u16::from_be_bytes(len_bytes) as usize;
        if len == 0 {
            return Ok(None);
        }
        if len > VMESS_MAX_CHUNK {
            return Err(CoreError::MalformedVmessRequest);
        }
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await?;
        Ok(Some(payload))
    }
}

#[derive(Clone)]
struct VmessWriter {
    iv: [u8; 16],
    nonce: u32,
    masked: bool,
}

impl VmessWriter {
    async fn write_chunk<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        payload: &[u8],
    ) -> Result<(), CoreError> {
        for chunk in payload.chunks(VMESS_MAX_CHUNK) {
            let mut len = u16::try_from(chunk.len())
                .map_err(|_| CoreError::MalformedVmessRequest)?
                .to_be_bytes();
            if self.masked {
                vmess_mask_length(&mut len, &self.iv, self.nonce);
            }
            self.nonce = self.nonce.wrapping_add(1);
            stream.write_all(&len).await?;
            stream.write_all(chunk).await?;
        }
        Ok(())
    }

    async fn write_end<S: AsyncWrite + Unpin>(&mut self, stream: &mut S) -> Result<(), CoreError> {
        let mut len = [0_u8; 2];
        if self.masked {
            vmess_mask_length(&mut len, &self.iv, self.nonce);
        }
        self.nonce = self.nonce.wrapping_add(1);
        stream.write_all(&len).await?;
        Ok(())
    }
}

struct VmessRequest {
    destination: Destination,
    response_auth: u8,
    body_iv: [u8; 16],
    options: u8,
}

fn vmess_command_key(id: &Uuid) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, id.as_bytes());
    Md5Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    hasher.finalize().into()
}

fn vmess_kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    type HmacSha256 = Hmac<Sha256>;
    let mut value = b"VMess AEAD KDF".to_vec();
    for segment in path {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(segment).expect("HMAC accepts any key");
        hmac::Mac::update(&mut mac, &value);
        value = mac.finalize().into_bytes().to_vec();
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&value).expect("HMAC accepts any key");
    hmac::Mac::update(&mut mac, key);
    let result = mac.finalize().into_bytes();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

fn vmess_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> [u8; 16] {
    let mut plain = [0_u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    OsRng.fill_bytes(&mut plain[8..12]);
    let crc = crc32fast::hash(&plain[..12]);
    plain[12..].copy_from_slice(&crc.to_be_bytes());
    let key = vmess_kdf16(cmd_key, &[VMESS_AEAD_AUTH_ID_ENCRYPTION]);
    let cipher = Aes128::new((&key).into());
    let mut block = GenericArray::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn vmess_decrypt_auth_id(auth_id: &[u8; 16], cmd_key: &[u8; 16]) -> Result<i64, CoreError> {
    let key = vmess_kdf16(cmd_key, &[VMESS_AEAD_AUTH_ID_ENCRYPTION]);
    let cipher = Aes128::new((&key).into());
    let mut block = GenericArray::clone_from_slice(auth_id);
    use aes::cipher::BlockDecrypt;
    cipher.decrypt_block(&mut block);
    let crc = crc32fast::hash(&block[..12]);
    if block[12..] != crc.to_be_bytes() {
        return Err(CoreError::InvalidVmessAuthId);
    }
    let mut ts = [0_u8; 8];
    ts.copy_from_slice(&block[..8]);
    Ok(i64::from_be_bytes(ts))
}

fn vmess_aead_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    plain: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes128Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: plain,
                aad: ad,
            },
        )
        .map_err(|_| CoreError::VmessDecryptFailed)
}

fn vmess_aead_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    encrypted: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes128Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: encrypted,
                aad: ad,
            },
        )
        .map_err(|_| CoreError::VmessDecryptFailed)
}

async fn accept_vmess<S>(
    stream: &mut S,
    inbound: &InboundConfig,
    replay_cache: &VmessReplayCache,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + Unpin,
{
    let settings = inbound
        .settings
        .as_ref()
        .ok_or(CoreError::MissingVmessClients)?;
    let clients = settings
        .clients
        .iter()
        .filter_map(|client| client.id.as_deref().and_then(|id| Uuid::parse_str(id).ok()))
        .collect::<Vec<_>>();
    if clients.is_empty() {
        return Err(CoreError::MissingVmessClients);
    }
    let (request, _client_id) = read_vmess_request(stream, &clients, Some(replay_cache)).await?;
    let response_iv = vmess_response_derive(&request.body_iv);
    let masked = request.options & VMESS_OPTION_CHUNK_MASKING != 0;
    Ok(AcceptedInbound {
        destination: request.destination,
        remote_prefix: Vec::new(),
        client_prefix: Vec::new(),
        shadowsocks: None,
        vmess: Some(VmessSession {
            reader: VmessReader {
                iv: request.body_iv,
                nonce: 0,
                masked,
            },
            writer: VmessWriter {
                iv: response_iv,
                nonce: 0,
                masked,
            },
            response_auth: request.response_auth,
        }),
        socks_udp: None,
    })
}

async fn read_vmess_request<S>(
    stream: &mut S,
    clients: &[Uuid],
    replay_cache: Option<&VmessReplayCache>,
) -> Result<(VmessRequest, Uuid), CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut auth_id = [0_u8; 16];
    stream.read_exact(&mut auth_id).await?;
    let mut matched = None;
    let now = current_unix_time();
    for id in clients {
        let cmd_key = vmess_command_key(id);
        if let Ok(timestamp) = vmess_decrypt_auth_id(&auth_id, &cmd_key)
            && (timestamp - now).abs() <= 120
        {
            matched = Some((*id, cmd_key));
            break;
        }
    }
    let (client_id, cmd_key) = matched.ok_or(CoreError::InvalidVmessClient)?;
    if let Some(replay_cache) = replay_cache {
        replay_cache.check_and_insert(auth_id, now)?;
    }

    let mut encrypted_len = [0_u8; 18];
    stream.read_exact(&mut encrypted_len).await?;
    let mut connection_nonce = [0_u8; 8];
    stream.read_exact(&mut connection_nonce).await?;
    let len_key = vmess_kdf16(&cmd_key, &[VMESS_AEAD_LENGTH_KEY, &connection_nonce]);
    let len_nonce = vmess_kdf16(&cmd_key, &[VMESS_AEAD_LENGTH_NONCE, &connection_nonce]);
    let plain_len = vmess_aead_decrypt(&len_key, &len_nonce, &encrypted_len, &auth_id)?;
    if plain_len.len() != 2 {
        return Err(CoreError::MalformedVmessRequest);
    }
    let payload_len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
    let mut encrypted_payload = vec![0_u8; payload_len + 16];
    stream.read_exact(&mut encrypted_payload).await?;
    let payload_key = vmess_kdf16(&cmd_key, &[VMESS_AEAD_HEADER_KEY, &connection_nonce]);
    let payload_nonce = vmess_kdf16(&cmd_key, &[VMESS_AEAD_HEADER_NONCE, &connection_nonce]);
    let payload = vmess_aead_decrypt(&payload_key, &payload_nonce, &encrypted_payload, &auth_id)?;
    Ok((parse_vmess_instruction(&payload)?, client_id))
}

fn parse_vmess_instruction(data: &[u8]) -> Result<VmessRequest, CoreError> {
    if data.len() < 43 || data[0] != 1 {
        return Err(CoreError::MalformedVmessRequest);
    }
    let checksum_at = data.len() - 4;
    let checksum = fnv1a(&data[..checksum_at]);
    if data[checksum_at..] != checksum.to_be_bytes() {
        return Err(CoreError::MalformedVmessRequest);
    }
    let mut body_iv = [0_u8; 16];
    body_iv.copy_from_slice(&data[1..17]);
    let response_auth = data[33];
    let options = data[34];
    let padding_security = data[35];
    let padding_len = usize::from(padding_security >> 4);
    let security = padding_security & 0x0f;
    if security != VMESS_SECURITY_NONE {
        return Err(CoreError::UnsupportedVmessSecurity(security));
    }
    if data[36] != 0 {
        return Err(CoreError::MalformedVmessRequest);
    }
    let command = data[37];
    if command != 1 {
        return Err(CoreError::UnsupportedVmessCommand(command));
    }
    let port = u16::from_be_bytes([data[38], data[39]]);
    let (host, offset) = parse_vmess_host(data, 40)?;
    if offset + padding_len + 4 != data.len() {
        return Err(CoreError::MalformedVmessRequest);
    }
    Ok(VmessRequest {
        destination: Destination::tcp(host, port),
        response_auth,
        body_iv,
        options,
    })
}

fn parse_vmess_host(data: &[u8], offset: usize) -> Result<(DestinationHost, usize), CoreError> {
    let address_type = *data.get(offset).ok_or(CoreError::MalformedVmessRequest)?;
    match address_type {
        1 if data.len() >= offset + 5 => Ok((
            DestinationHost::Ip(IpAddr::from([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ])),
            offset + 5,
        )),
        2 if data.len() >= offset + 2 => {
            let len = data[offset + 1] as usize;
            if data.len() < offset + 2 + len {
                return Err(CoreError::MalformedVmessRequest);
            }
            let domain = str::from_utf8(&data[offset + 2..offset + 2 + len])
                .map_err(|_| CoreError::MalformedVmessRequest)?;
            Ok((
                DestinationHost::parse(domain).map_err(|_| CoreError::MalformedVmessRequest)?,
                offset + 2 + len,
            ))
        }
        3 if data.len() >= offset + 17 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&data[offset + 1..offset + 17]);
            Ok((DestinationHost::Ip(IpAddr::from(octets)), offset + 17))
        }
        other => Err(CoreError::UnsupportedVmessAddress(other)),
    }
}

fn build_vmess_request(
    id: &Uuid,
    destination: &Destination,
) -> Result<(Vec<u8>, VmessSession), CoreError> {
    let cmd_key = vmess_command_key(id);
    let mut body_iv = [0_u8; 16];
    let mut body_key = [0_u8; 16];
    let mut connection_nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut body_iv);
    OsRng.fill_bytes(&mut body_key);
    OsRng.fill_bytes(&mut connection_nonce);
    let response_auth = body_iv[0];
    let options = VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING;
    let mut instruction = Vec::new();
    instruction.push(1);
    instruction.extend_from_slice(&body_iv);
    instruction.extend_from_slice(&body_key);
    instruction.push(response_auth);
    instruction.push(options);
    instruction.push(VMESS_SECURITY_NONE);
    instruction.push(0);
    instruction.push(1);
    instruction.extend_from_slice(&destination.port.to_be_bytes());
    encode_vmess_host(&mut instruction, &destination.host)?;
    let checksum = fnv1a(&instruction);
    instruction.extend_from_slice(&checksum.to_be_bytes());

    let auth_id = vmess_auth_id(&cmd_key, current_unix_time());
    let len_key = vmess_kdf16(&cmd_key, &[VMESS_AEAD_LENGTH_KEY, &connection_nonce]);
    let len_nonce = vmess_kdf16(&cmd_key, &[VMESS_AEAD_LENGTH_NONCE, &connection_nonce]);
    let payload_key = vmess_kdf16(&cmd_key, &[VMESS_AEAD_HEADER_KEY, &connection_nonce]);
    let payload_nonce = vmess_kdf16(&cmd_key, &[VMESS_AEAD_HEADER_NONCE, &connection_nonce]);
    let encrypted_len = vmess_aead_encrypt(
        &len_key,
        &len_nonce,
        &(instruction.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let encrypted_payload =
        vmess_aead_encrypt(&payload_key, &payload_nonce, &instruction, &auth_id)?;
    let mut out = Vec::with_capacity(16 + encrypted_len.len() + 8 + encrypted_payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted_len);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&encrypted_payload);
    let response_iv = vmess_response_derive(&body_iv);
    Ok((
        out,
        VmessSession {
            reader: VmessReader {
                iv: response_iv,
                nonce: 0,
                masked: true,
            },
            writer: VmessWriter {
                iv: body_iv,
                nonce: 0,
                masked: true,
            },
            response_auth,
        },
    ))
}

fn encode_vmess_host(out: &mut Vec<u8>, host: &DestinationHost) -> Result<(), CoreError> {
    match host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        DestinationHost::Domain(domain) => {
            out.push(2);
            out.push(u8::try_from(domain.len()).map_err(|_| CoreError::MalformedVmessRequest)?);
            out.extend_from_slice(domain.as_bytes());
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

async fn connect_vmess_upstream(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<(OutboundStream, VmessSession), CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|s| s.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    if server
        .security
        .as_deref()
        .is_some_and(|security| security != "none")
    {
        return Err(CoreError::UnsupportedVmessSecurity(0));
    }
    let id = server
        .id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or(CoreError::MissingVmessSettings)?;
    let mut remote = connect_proxy_stream(outbound).await?;
    let (header, session) = build_vmess_request(&id, destination)?;
    remote.write_all(&header).await?;
    read_vmess_response_header(&mut remote, &session).await?;
    Ok((remote, session))
}

async fn read_vmess_response_header<S>(
    stream: &mut S,
    session: &VmessSession,
) -> Result<(), CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut encrypted_len = [0_u8; 18];
    stream.read_exact(&mut encrypted_len).await?;
    let len_key = vmess_kdf16(&session.reader.iv, &[VMESS_AEAD_RESP_LENGTH_KEY]);
    let len_iv = vmess_kdf16(&session.reader.iv, &[VMESS_AEAD_RESP_LENGTH_IV]);
    let plain_len = vmess_aead_decrypt(&len_key, &len_iv, &encrypted_len, &[])?;
    if plain_len.len() != 2 {
        return Err(CoreError::MalformedVmessRequest);
    }
    let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
    let mut encrypted_header = vec![0_u8; len + 16];
    stream.read_exact(&mut encrypted_header).await?;
    let key = vmess_kdf16(&session.reader.iv, &[VMESS_AEAD_RESP_KEY]);
    let iv = vmess_kdf16(&session.reader.iv, &[VMESS_AEAD_RESP_IV]);
    let header = vmess_aead_decrypt(&key, &iv, &encrypted_header, &[])?;
    if header.len() < 2 || header[0] != session.response_auth {
        return Err(CoreError::MalformedVmessRequest);
    }
    Ok(())
}

async fn write_vmess_response_header<S>(
    stream: &mut S,
    session: &VmessSession,
    response_auth: u8,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    let header = [response_auth, 0];
    let len_key = vmess_kdf16(&session.writer.iv, &[VMESS_AEAD_RESP_LENGTH_KEY]);
    let len_iv = vmess_kdf16(&session.writer.iv, &[VMESS_AEAD_RESP_LENGTH_IV]);
    let key = vmess_kdf16(&session.writer.iv, &[VMESS_AEAD_RESP_KEY]);
    let iv = vmess_kdf16(&session.writer.iv, &[VMESS_AEAD_RESP_IV]);
    let encrypted_len =
        vmess_aead_encrypt(&len_key, &len_iv, &(header.len() as u16).to_be_bytes(), &[])?;
    let encrypted_header = vmess_aead_encrypt(&key, &iv, &header, &[])?;
    stream.write_all(&encrypted_len).await?;
    stream.write_all(&encrypted_header).await?;
    Ok(())
}

fn vmess_response_derive(value: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(value);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn vmess_mask_length(length: &mut [u8; 2], iv: &[u8; 16], nonce: u32) {
    let mut hasher = Shake128::default();
    hasher.update(iv);
    hasher.update(&nonce.to_be_bytes());
    let mut reader = hasher.finalize_xof();
    let mut mask = [0_u8; 2];
    reader.read(&mut mask);
    length[0] ^= mask[0];
    length[1] ^= mask[1];
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn inbound_accounts(inbound: &InboundConfig) -> &[xrs_config::InboundAccountConfig] {
    inbound
        .settings
        .as_ref()
        .map_or(&[], |settings| settings.accounts.as_slice())
}

async fn accept_socks5<S>(
    stream: &mut S,
    inbound: &InboundConfig,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let accounts = inbound_accounts(inbound);
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(CoreError::UnsupportedSocksVersion(greeting[0]));
    }

    let method_count = usize::from(greeting[1]);
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;
    if accounts.is_empty() {
        if !methods.contains(&0x00) {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(CoreError::UnsupportedSocksMethod);
        }
        stream.write_all(&[0x05, 0x00]).await?;
    } else {
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(CoreError::UnsupportedSocksMethod);
        }
        stream.write_all(&[0x05, 0x02]).await?;
        accept_socks5_password_auth(stream, accounts).await?;
    }

    let request = read_socks_request(stream).await?;
    match request.command {
        0x01 => {
            write_socks_success(stream, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
            Ok(AcceptedInbound::new(request.destination))
        }
        0x03 => {
            let listen = inbound
                .listen
                .unwrap_or_else(|| "127.0.0.1".parse().expect("valid loopback"));
            let socket = UdpSocket::bind(SocketAddr::new(listen, 0)).await?;
            let bind_addr = socket.local_addr()?;
            write_socks_success(stream, bind_addr).await?;
            let mut accepted = AcceptedInbound::new(request.destination);
            accepted.socks_udp = Some(SocksUdpAssociate { socket });
            Ok(accepted)
        }
        command => Err(CoreError::UnsupportedSocksCommand(command)),
    }
}

async fn read_socks_request<S>(stream: &mut S) -> Result<SocksRequest, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(CoreError::UnsupportedSocksVersion(header[0]));
    }
    let host = read_socks_host(stream, header[3]).await?;
    let port = read_port(stream).await?;
    let network = if header[1] == 0x03 {
        Network::Udp
    } else {
        Network::Tcp
    };
    Ok(SocksRequest {
        command: header[1],
        destination: Destination {
            host,
            port,
            network,
        },
    })
}

async fn write_socks_success<S>(stream: &mut S, bind_addr: SocketAddr) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    let mut response = vec![0x05, 0x00, 0x00];
    match bind_addr.ip() {
        IpAddr::V4(ip) => {
            response.push(0x01);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(0x04);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&bind_addr.port().to_be_bytes());
    stream.write_all(&response).await?;
    Ok(())
}

async fn accept_socks5_password_auth<S>(
    stream: &mut S,
    accounts: &[xrs_config::InboundAccountConfig],
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0_u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 0x01 {
        stream.write_all(&[0x01, 0x01]).await?;
        return Err(CoreError::ProxyAuthenticationFailed);
    }
    let username = read_socks_auth_field(stream).await?;
    let password = read_socks_auth_field(stream).await?;
    if accounts
        .iter()
        .any(|account| account.user.as_bytes() == username && account.pass.as_bytes() == password)
    {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[0x01, 0x01]).await?;
        Err(CoreError::ProxyAuthenticationFailed)
    }
}

async fn read_socks_auth_field<S>(stream: &mut S) -> Result<Vec<u8>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 1];
    stream.read_exact(&mut len).await?;
    let mut value = vec![0_u8; usize::from(len[0])];
    stream.read_exact(&mut value).await?;
    Ok(value)
}

async fn read_socks_host<S>(stream: &mut S, address_type: u8) -> Result<DestinationHost, CoreError>
where
    S: AsyncRead + Unpin,
{
    match address_type {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Ok(DestinationHost::Ip(octets.into()))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8_lossy(&domain);
            DestinationHost::parse(&domain)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error).into())
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            Ok(DestinationHost::Ip(octets.into()))
        }
        other => Err(CoreError::UnsupportedSocksAddress(other)),
    }
}

async fn read_port<S>(stream: &mut S) -> Result<u16, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn accept_http<S>(
    stream: &mut S,
    inbound: &InboundConfig,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_header(stream).await?;
    let header = str::from_utf8(&request).map_err(|_| CoreError::InvalidHttpTarget)?;
    let line_end = header.find("\r\n").ok_or(CoreError::InvalidHttpTarget)?;
    let accounts = inbound_accounts(inbound);
    if !accounts.is_empty() && !http_proxy_auth_matches(header, accounts) {
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(CoreError::ProxyAuthenticationFailed);
    }
    let request_line = &header[..line_end];
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(CoreError::UnsupportedHttpRequest)?;
    let target = parts.next().ok_or(CoreError::InvalidHttpTarget)?;
    let version = parts.next().ok_or(CoreError::InvalidHttpTarget)?;
    if parts.next().is_some() {
        return Err(CoreError::InvalidHttpTarget);
    }

    if method == "CONNECT" {
        let destination = parse_http_connect_target(target)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return Ok(AcceptedInbound::new(destination));
    }

    if !is_http_token(method) || !target.starts_with("http://") {
        return Err(CoreError::UnsupportedHttpRequest);
    }

    let (destination, path) = parse_http_absolute_target(target)?;
    let mut remote_prefix = Vec::with_capacity(request.len());
    remote_prefix.extend_from_slice(method.as_bytes());
    remote_prefix.push(b' ');
    remote_prefix.extend_from_slice(path.as_bytes());
    remote_prefix.push(b' ');
    remote_prefix.extend_from_slice(version.as_bytes());
    remote_prefix.extend_from_slice(&request[line_end..]);

    Ok(AcceptedInbound {
        destination,
        remote_prefix,
        client_prefix: Vec::new(),
        shadowsocks: None,
        vmess: None,
        socks_udp: None,
    })
}

fn http_proxy_auth_matches(header: &str, accounts: &[xrs_config::InboundAccountConfig]) -> bool {
    header.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("Proxy-Authorization")
            && value
                .trim_start()
                .strip_prefix("Basic ")
                .is_some_and(|encoded| {
                    decode_base64(encoded.trim()).is_some_and(|decoded| {
                        accounts.iter().any(|account| {
                            let expected = format!("{}:{}", account.user, account.pass);
                            decoded == expected.as_bytes()
                        })
                    })
                })
    })
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut padding = false;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' if !padding => u32::from(byte - b'A'),
            b'a'..=b'z' if !padding => u32::from(byte - b'a' + 26),
            b'0'..=b'9' if !padding => u32::from(byte - b'0' + 52),
            b'+' if !padding => 62,
            b'/' if !padding => 63,
            b'=' => {
                padding = true;
                continue;
            }
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(output)
}

async fn read_http_header<S>(stream: &mut S) -> Result<Vec<u8>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    let mut complete = false;
    while request.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(CoreError::HttpHeaderTooLarge);
    }
    Ok(request)
}

fn parse_http_connect_target(target: &str) -> Result<Destination, CoreError> {
    let (host, port) = split_http_host_port(target, None)?;
    Ok(Destination::tcp(host, port))
}

fn parse_http_absolute_target(target: &str) -> Result<(Destination, &str), CoreError> {
    let rest = target
        .strip_prefix("http://")
        .ok_or(CoreError::UnsupportedHttpRequest)?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(CoreError::InvalidHttpTarget);
    }
    let path = if authority_end == rest.len() {
        "/"
    } else if rest[authority_end..].starts_with('?') {
        &target[("http://".len() + authority_end)..]
    } else {
        &rest[authority_end..]
    };
    let (host, port) = split_http_host_port(authority, Some(80))?;
    Ok((Destination::tcp(host, port), path))
}

fn split_http_host_port(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(DestinationHost, u16), CoreError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(CoreError::InvalidHttpTarget)?;
        let host = &rest[..end];
        let rest = &rest[(end + 1)..];
        let port = if let Some(port) = rest.strip_prefix(':') {
            port.parse::<u16>()
                .map_err(|_| CoreError::InvalidHttpTarget)?
        } else if rest.is_empty() {
            default_port.ok_or(CoreError::InvalidHttpTarget)?
        } else {
            return Err(CoreError::InvalidHttpTarget);
        };
        (host, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| CoreError::InvalidHttpTarget)?;
                (host, port)
            }
            Some(_) => return Err(CoreError::InvalidHttpTarget),
            None => (authority, default_port.ok_or(CoreError::InvalidHttpTarget)?),
        };
        (host, port)
    };
    if host.is_empty() {
        return Err(CoreError::InvalidHttpTarget);
    }
    let host = DestinationHost::parse(host)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok((host, port))
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

fn shadowsocks_password_key(password: &str) -> [u8; SHADOWSOCKS_KEY_LEN] {
    let mut key = Vec::new();
    let mut previous = Vec::new();
    while key.len() < SHADOWSOCKS_KEY_LEN {
        let mut hasher = Md5::new();
        Md5Digest::update(&mut hasher, &previous);
        Md5Digest::update(&mut hasher, password.as_bytes());
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    let mut result = [0_u8; SHADOWSOCKS_KEY_LEN];
    result.copy_from_slice(&key[..SHADOWSOCKS_KEY_LEN]);
    result
}

fn shadowsocks_subkey(
    key: &[u8; SHADOWSOCKS_KEY_LEN],
    salt: &[u8; SHADOWSOCKS_SALT_LEN],
) -> Result<[u8; SHADOWSOCKS_KEY_LEN], CoreError> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut subkey = [0_u8; SHADOWSOCKS_KEY_LEN];
    hk.expand(b"ss-subkey", &mut subkey)
        .map_err(|_| CoreError::ShadowsocksDecryptFailed)?;
    Ok(subkey)
}

struct ShadowsocksSession {
    reader: ShadowsocksReader,
    writer: ShadowsocksWriter,
    pending: Vec<u8>,
}

impl ShadowsocksSession {
    fn new(
        key: [u8; SHADOWSOCKS_KEY_LEN],
        read_salt: [u8; SHADOWSOCKS_SALT_LEN],
        write_salt: [u8; SHADOWSOCKS_SALT_LEN],
    ) -> Result<Self, CoreError> {
        Ok(Self {
            reader: ShadowsocksReader::new(key, Some(read_salt))?,
            writer: ShadowsocksWriter::new(key, write_salt)?,
            pending: Vec::new(),
        })
    }

    fn new_lazy_reader(
        key: [u8; SHADOWSOCKS_KEY_LEN],
        write_salt: [u8; SHADOWSOCKS_SALT_LEN],
    ) -> Result<Self, CoreError> {
        Ok(Self {
            reader: ShadowsocksReader::new(key, None)?,
            writer: ShadowsocksWriter::new(key, write_salt)?,
            pending: Vec::new(),
        })
    }
}

struct ShadowsocksReader {
    key: [u8; SHADOWSOCKS_KEY_LEN],
    cipher: Option<ChaCha20Poly1305>,
    nonce: u128,
}

impl ShadowsocksReader {
    fn new(
        key: [u8; SHADOWSOCKS_KEY_LEN],
        salt: Option<[u8; SHADOWSOCKS_SALT_LEN]>,
    ) -> Result<Self, CoreError> {
        let cipher = salt
            .map(|salt| shadowsocks_subkey(&key, &salt))
            .transpose()?
            .map(|subkey| ChaCha20Poly1305::new((&subkey).into()));
        Ok(Self {
            key,
            cipher,
            nonce: 0,
        })
    }

    async fn read_chunk<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        if self.cipher.is_none() {
            let mut salt = [0_u8; SHADOWSOCKS_SALT_LEN];
            match stream.read_exact(&mut salt).await {
                Ok(_) => self.init_cipher(salt)?,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        let mut encrypted_len = [0_u8; 2 + SHADOWSOCKS_TAG_LEN];
        match stream.read_exact(&mut encrypted_len).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let len = self.decrypt(&encrypted_len)?;
        if len.len() != 2 {
            return Err(CoreError::ShadowsocksDecryptFailed);
        }
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if payload_len > SHADOWSOCKS_MAX_CHUNK {
            return Err(CoreError::ShadowsocksDecryptFailed);
        }
        let mut encrypted_payload = vec![0_u8; payload_len + SHADOWSOCKS_TAG_LEN];
        stream.read_exact(&mut encrypted_payload).await?;
        self.decrypt(&encrypted_payload).map(Some)
    }

    fn init_cipher(&mut self, salt: [u8; SHADOWSOCKS_SALT_LEN]) -> Result<(), CoreError> {
        let subkey = shadowsocks_subkey(&self.key, &salt)?;
        self.cipher = Some(ChaCha20Poly1305::new((&subkey).into()));
        self.nonce = 0;
        Ok(())
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        let nonce = nonce_bytes(self.nonce);
        let plain = self
            .cipher
            .as_ref()
            .ok_or(CoreError::ShadowsocksDecryptFailed)?
            .decrypt((&nonce).into(), data)
            .map_err(|_| CoreError::ShadowsocksDecryptFailed)?;
        self.nonce += 1;
        Ok(plain)
    }
}

struct ShadowsocksWriter {
    cipher: ChaCha20Poly1305,
    nonce: u128,
}

impl ShadowsocksWriter {
    fn new(
        key: [u8; SHADOWSOCKS_KEY_LEN],
        salt: [u8; SHADOWSOCKS_SALT_LEN],
    ) -> Result<Self, CoreError> {
        let subkey = shadowsocks_subkey(&key, &salt)?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new((&subkey).into()),
            nonce: 0,
        })
    }

    async fn write_chunk<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        payload: &[u8],
    ) -> Result<(), CoreError> {
        for chunk in payload.chunks(SHADOWSOCKS_MAX_CHUNK) {
            let len = u16::try_from(chunk.len())
                .map_err(|_| CoreError::ShadowsocksDecryptFailed)?
                .to_be_bytes();
            let encrypted_len = self.encrypt(&len)?;
            let encrypted_payload = self.encrypt(chunk)?;
            stream.write_all(&encrypted_len).await?;
            stream.write_all(&encrypted_payload).await?;
        }
        Ok(())
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        let nonce = nonce_bytes(self.nonce);
        let encrypted = self
            .cipher
            .encrypt((&nonce).into(), data)
            .map_err(|_| CoreError::ShadowsocksDecryptFailed)?;
        self.nonce += 1;
        Ok(encrypted)
    }
}

fn nonce_bytes(value: u128) -> [u8; SHADOWSOCKS_NONCE_LEN] {
    let mut nonce = [0_u8; SHADOWSOCKS_NONCE_LEN];
    nonce[..8].copy_from_slice(&(value as u64).to_le_bytes());
    nonce
}

async fn accept_shadowsocks<S>(
    stream: &mut S,
    inbound: &InboundConfig,
) -> Result<AcceptedInbound, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let settings = inbound
        .settings
        .as_ref()
        .ok_or(CoreError::MissingShadowsocksSettings)?;
    if settings.method.as_deref() != Some(SHADOWSOCKS_METHOD) {
        return Err(CoreError::UnsupportedShadowsocksMethod);
    }
    let password = settings
        .password
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or(CoreError::MissingShadowsocksSettings)?;
    let key = shadowsocks_password_key(password);
    let mut read_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
    stream.read_exact(&mut read_salt).await?;
    let mut write_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
    OsRng.fill_bytes(&mut write_salt);
    stream.write_all(&write_salt).await?;
    let mut session = ShadowsocksSession::new(key, read_salt, write_salt)?;
    let first = session
        .reader
        .read_chunk(stream)
        .await?
        .ok_or(CoreError::MalformedShadowsocksAddress)?;
    let (destination, offset) = parse_shadowsocks_address(&first)?;
    session.pending.extend_from_slice(&first[offset..]);
    Ok(AcceptedInbound {
        destination,
        remote_prefix: Vec::new(),
        client_prefix: Vec::new(),
        shadowsocks: Some(session),
        vmess: None,
        socks_udp: None,
    })
}

async fn connect_shadowsocks_upstream(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<(OutboundStream, ShadowsocksSession), CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|s| s.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    if server.method.as_deref() != Some(SHADOWSOCKS_METHOD) {
        return Err(CoreError::UnsupportedShadowsocksMethod);
    }
    let password = server
        .password
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or(CoreError::MissingShadowsocksSettings)?;
    let mut remote = connect_proxy_stream(outbound).await?;
    let key = shadowsocks_password_key(password);
    let mut write_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
    OsRng.fill_bytes(&mut write_salt);
    remote.write_all(&write_salt).await?;
    let mut session = ShadowsocksSession::new_lazy_reader(key, write_salt)?;
    let header = encode_shadowsocks_address(destination)?;
    session.writer.write_chunk(&mut remote, &header).await?;
    Ok((remote, session))
}

fn parse_shadowsocks_address(data: &[u8]) -> Result<(Destination, usize), CoreError> {
    if data.is_empty() {
        return Err(CoreError::MalformedShadowsocksAddress);
    }
    match data[0] {
        1 if data.len() >= 7 => Ok((
            Destination::tcp(
                DestinationHost::Ip(IpAddr::from([data[1], data[2], data[3], data[4]])),
                u16::from_be_bytes([data[5], data[6]]),
            ),
            7,
        )),
        3 if data.len() >= 2 => {
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(CoreError::MalformedShadowsocksAddress);
            }
            let domain = str::from_utf8(&data[2..2 + len])
                .map_err(|_| CoreError::MalformedShadowsocksAddress)?;
            let port_offset = 2 + len;
            let host = DestinationHost::parse(domain)
                .map_err(|_| CoreError::MalformedShadowsocksAddress)?;
            Ok((
                Destination::tcp(
                    host,
                    u16::from_be_bytes([data[port_offset], data[port_offset + 1]]),
                ),
                port_offset + 2,
            ))
        }
        4 if data.len() >= 19 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&data[1..17]);
            Ok((
                Destination::tcp(
                    DestinationHost::Ip(IpAddr::from(octets)),
                    u16::from_be_bytes([data[17], data[18]]),
                ),
                19,
            ))
        }
        _ => Err(CoreError::MalformedShadowsocksAddress),
    }
}

fn encode_shadowsocks_address(destination: &Destination) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    match &destination.host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        DestinationHost::Domain(domain) => {
            out.push(3);
            out.push(
                u8::try_from(domain.len()).map_err(|_| CoreError::MalformedShadowsocksAddress)?,
            );
            out.extend_from_slice(domain.as_bytes());
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

fn encrypt_shadowsocks_udp_packet(
    key: [u8; SHADOWSOCKS_KEY_LEN],
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut salt = [0_u8; SHADOWSOCKS_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let subkey = shadowsocks_subkey(&key, &salt)?;
    let cipher = ChaCha20Poly1305::new((&subkey).into());
    let mut plain = encode_shadowsocks_address(destination)?;
    plain.extend_from_slice(payload);
    let encrypted = cipher
        .encrypt((&nonce_bytes(0)).into(), plain.as_slice())
        .map_err(|_| CoreError::ShadowsocksDecryptFailed)?;
    let mut packet = salt.to_vec();
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn decrypt_shadowsocks_udp_packet(
    key: [u8; SHADOWSOCKS_KEY_LEN],
    packet: &[u8],
) -> Result<(Destination, Vec<u8>), CoreError> {
    if packet.len() <= SHADOWSOCKS_SALT_LEN + SHADOWSOCKS_TAG_LEN {
        return Err(CoreError::ShadowsocksDecryptFailed);
    }
    let mut salt = [0_u8; SHADOWSOCKS_SALT_LEN];
    salt.copy_from_slice(&packet[..SHADOWSOCKS_SALT_LEN]);
    let subkey = shadowsocks_subkey(&key, &salt)?;
    let cipher = ChaCha20Poly1305::new((&subkey).into());
    let plain = cipher
        .decrypt((&nonce_bytes(0)).into(), &packet[SHADOWSOCKS_SALT_LEN..])
        .map_err(|_| CoreError::ShadowsocksDecryptFailed)?;
    let (mut destination, offset) = parse_shadowsocks_address(&plain)?;
    destination.network = Network::Udp;
    Ok((destination, plain[offset..].to_vec()))
}

async fn send_shadowsocks_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    if server.method.as_deref() != Some(SHADOWSOCKS_METHOD) {
        return Err(CoreError::UnsupportedShadowsocksMethod);
    }
    let password = server
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or(CoreError::MissingShadowsocksSettings)?;
    let key = shadowsocks_password_key(password);
    let request = encrypt_shadowsocks_udp_packet(key, destination, payload)?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket
        .connect((server.address.as_str(), server.port))
        .await?;
    timeout(DNS_TIMEOUT, socket.send(&request))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let mut response = vec![0_u8; 65535];
    let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    response.truncate(length);
    let (response_destination, response_payload) = decrypt_shadowsocks_udp_packet(key, &response)?;
    Ok(UdpPayloadResponse {
        destination: response_destination,
        payload: response_payload,
    })
}

async fn relay_shadowsocks_to_plain<R>(
    client: InboundStream,
    mut session: ShadowsocksSession,
    mut remote: R,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    if !session.pending.is_empty() {
        remote.write_all(&session.pending).await?;
        counters.add_uplink(session.pending.len() as u64);
        session.pending.clear();
    }
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut total = 0;
        while let Some(chunk) = session.reader.read_chunk(&mut cr).await? {
            total += chunk.len() as u64;
            rw.write_all(&chunk).await?;
        }
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut writer = session.writer;
        let mut buf = [0_u8; 8192];
        let mut total = 0;
        loop {
            let n = rr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            writer.write_chunk(&mut cw, &buf[..n]).await?;
        }
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

async fn relay_plain_to_shadowsocks<R>(
    client: InboundStream,
    remote: R,
    mut session: ShadowsocksSession,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut writer = session.writer;
        let mut buf = [0_u8; 8192];
        let mut total = 0;
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            writer.write_chunk(&mut rw, &buf[..n]).await?;
        }
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut total = 0;
        while let Some(chunk) = session.reader.read_chunk(&mut rr).await? {
            total += chunk.len() as u64;
            cw.write_all(&chunk).await?;
        }
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

async fn relay_shadowsocks_to_shadowsocks<R>(
    client: InboundStream,
    inbound: ShadowsocksSession,
    remote: R,
    outbound: ShadowsocksSession,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut reader = inbound.reader;
        let mut writer = outbound.writer;
        let mut pending = inbound.pending;
        let mut total = 0;
        if !pending.is_empty() {
            total += pending.len() as u64;
            writer.write_chunk(&mut rw, &pending).await?;
            pending.clear();
        }
        while let Some(chunk) = reader.read_chunk(&mut cr).await? {
            total += chunk.len() as u64;
            writer.write_chunk(&mut rw, &chunk).await?;
        }
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut reader = outbound.reader;
        let mut writer = inbound.writer;
        let mut total = 0;
        while let Some(chunk) = reader.read_chunk(&mut rr).await? {
            total += chunk.len() as u64;
            writer.write_chunk(&mut cw, &chunk).await?;
        }
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

async fn relay_vmess_to_plain<R>(
    mut client: InboundStream,
    mut session: VmessSession,
    remote: R,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    write_vmess_response_header(&mut client, &session, session.response_auth).await?;
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut total = 0;
        while let Some(chunk) = session.reader.read_chunk(&mut cr).await? {
            total += chunk.len() as u64;
            rw.write_all(&chunk).await?;
        }
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut writer = session.writer;
        let mut buf = [0_u8; 8192];
        let mut total = 0;
        loop {
            let n = rr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            writer.write_chunk(&mut cw, &buf[..n]).await?;
        }
        writer.write_end(&mut cw).await?;
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

async fn relay_plain_to_vmess<R>(
    client: InboundStream,
    remote: R,
    mut session: VmessSession,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut writer = session.writer;
        let mut buf = [0_u8; 8192];
        let mut total = 0;
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            writer.write_chunk(&mut rw, &buf[..n]).await?;
        }
        writer.write_end(&mut rw).await?;
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut total = 0;
        while let Some(chunk) = session.reader.read_chunk(&mut rr).await? {
            total += chunk.len() as u64;
            cw.write_all(&chunk).await?;
        }
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

async fn relay_vmess_to_vmess<R>(
    client: InboundStream,
    inbound: VmessSession,
    remote: R,
    outbound: VmessSession,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = io::split(client);
    let (mut rr, mut rw) = io::split(remote);
    let up = async move {
        let mut reader = inbound.reader;
        let mut writer = outbound.writer;
        let mut total = 0;
        while let Some(chunk) = reader.read_chunk(&mut cr).await? {
            total += chunk.len() as u64;
            writer.write_chunk(&mut rw, &chunk).await?;
        }
        writer.write_end(&mut rw).await?;
        rw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let down = async move {
        let mut reader = outbound.reader;
        let mut writer = inbound.writer;
        let mut total = 0;
        while let Some(chunk) = reader.read_chunk(&mut rr).await? {
            total += chunk.len() as u64;
            writer.write_chunk(&mut cw, &chunk).await?;
        }
        writer.write_end(&mut cw).await?;
        cw.shutdown().await?;
        Result::<u64, CoreError>::Ok(total)
    };
    let (uplink, downlink) = tokio::try_join!(up, down)?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

enum InboundStream {
    Tcp(TcpStream),
    Tls(tokio_native_tls::TlsStream<TcpStream>),
}

impl InboundStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr(),
            Self::Tls(stream) => stream.get_ref().get_ref().get_ref().peer_addr(),
        }
    }
}

impl AsyncRead for InboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

enum OutboundStream {
    Tcp(TcpStream),
    Tls(tokio_native_tls::TlsStream<TcpStream>),
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn connect_tcp(destination: &Destination) -> Result<TcpStream, CoreError> {
    timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((destination.host.to_string(), destination.port)),
    )
    .await
    .map_err(|_| CoreError::Timeout)?
    .map_err(Into::into)
}

fn outbound_uses_tls(outbound: &OutboundConfig) -> bool {
    outbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.security.as_deref())
        == Some("tls")
}

async fn connect_outbound_stream(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<OutboundStream, CoreError> {
    let use_tls = outbound_uses_tls(outbound);
    let tls_settings = outbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.tls_settings.as_ref());
    let server_name = if use_tls {
        Some(
            tls_settings
                .and_then(|settings| settings.server_name.as_deref())
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .or_else(|| match &destination.host {
                    DestinationHost::Domain(domain) => Some(domain.clone()),
                    DestinationHost::Ip(_) => None,
                })
                .ok_or(CoreError::MissingTlsServerName)?,
        )
    } else {
        None
    };
    let stream = connect_tcp(destination).await?;

    let Some(server_name) = server_name else {
        return Ok(OutboundStream::Tcp(stream));
    };
    let mut builder = TlsConnector::builder();
    if let Some(settings) = tls_settings {
        if settings.allow_insecure {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        if !settings.alpn.is_empty() {
            let protocols = settings.alpn.iter().map(String::as_str).collect::<Vec<_>>();
            builder.request_alpns(&protocols);
        }
    }
    let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
    let stream = timeout(CONNECT_TIMEOUT, connector.connect(&server_name, stream))
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(OutboundStream::Tls(stream))
}

async fn connect_freedom(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<OutboundStream, CoreError> {
    connect_outbound_stream(outbound, destination).await
}

async fn write_remote_prefix<S>(stream: &mut S, remote_prefix: &[u8]) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    if !remote_prefix.is_empty() {
        stream.write_all(remote_prefix).await?;
    }
    Ok(())
}

async fn write_client_prefix<S>(stream: &mut S, client_prefix: &[u8]) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    if !client_prefix.is_empty() {
        stream.write_all(client_prefix).await?;
    }
    Ok(())
}

async fn relay<C, R>(
    mut client: C,
    mut remote: R,
    counters: Arc<TrafficCounters>,
) -> Result<(), CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (uplink, downlink) = io::copy_bidirectional(&mut client, &mut remote).await?;
    counters.add_uplink(uplink);
    counters.add_downlink(downlink);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpSocket, UdpSocket};

    const TEST_TLS_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIDHzCCAgegAwIBAgIURdNAQnyu2TR+h7R6cVC1aAC3rSowDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUxNDAyMDM0NVoXDTI2MDUx\nNTAyMDM0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAtKu2mZGYeLrLYh5Xiyk9++IQobDf5yvIdYfMrupFKg0u\nsxpX5MrkNqG7B6qi3JUzeIbt8seA/AT+TxyafIoQpaI8aGVRJJoUMos7TJ8Ls/Be\nTjCMmYE0D8cBTZEkYfldMfg5MMbbpzlBkwe/RepecHn2Va9IGuicfFkoo6P4seDN\neZEUnWKTUfivVyIfsj6hj4/eHd5LdaYvjezZDBZdKBujdC5GLu2C4omTU6aPzcOm\nmLpvFl6RrvfVxO09tTNqV1OLaIBW91cRQA6ddUpUtO7wAyJKoT1bVbUeCANJwncr\nyYyzd3pJhLDxyTmKNMndo0GTLXnYe60LReBwhkoHKwIDAQABo2kwZzAdBgNVHQ4E\nFgQUcqcIWS47QVxOlXfOqQtURnn+g6QwHwYDVR0jBBgwFoAUcqcIWS47QVxOlXfO\nqQtURnn+g6QwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3Qw\nDQYJKoZIhvcNAQELBQADggEBALKCVoRVSvibh8S9pGnilIKM74E0Jf7zbiu0RRhs\nii1V2Sy+mWKjX7uSx9u0DpKJbPtoiwOSyePk3WC4T/JRqQaIo5hijecuRl8jf69z\nI2GwR/XDN5RpcA+kugRXuK+WXFJiKNV9qFuc4uLnwwreDSpXaCZXy7W4mkz8Dm6z\n9XOJOoGRF3BEIpYgXfz0PDbx+h0NpnrfO28kA/JAU9jfDFNgg0419GkWwM5GPaaj\nVVm4iAOVHU1RHlvF/hC2jYXKjyXUFsvrsN5qMdEKq3zyhjH4tpUHR/lUIyUj9/LR\nb2kXPF2jofG+oPeoTr19T7oTJQL31KLQJiHNoBmjfeD/uMk=\n-----END CERTIFICATE-----\n";
    const TEST_TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0q7aZkZh4usti\nHleLKT374hChsN/nK8h1h8yu6kUqDS6zGlfkyuQ2obsHqqLclTN4hu3yx4D8BP5P\nHJp8ihClojxoZVEkmhQyiztMnwuz8F5OMIyZgTQPxwFNkSRh+V0x+DkwxtunOUGT\nB79F6l5wefZVr0ga6Jx8WSijo/ix4M15kRSdYpNR+K9XIh+yPqGPj94d3kt1pi+N\n7NkMFl0oG6N0LkYu7YLiiZNTpo/Nw6aYum8WXpGu99XE7T21M2pXU4togFb3VxFA\nDp11SlS07vADIkqhPVtVtR4IA0nCdyvJjLN3ekmEsPHJOYo0yd2jQZMtedh7rQtF\n4HCGSgcrAgMBAAECggEAAjyEw0PJKRh3mV3+yJB9XaU1BHL7269ducX0XwwDJB1a\nnImE2NEgOIkXl2V3C/Xc17gkntf173HU80ks4SN8waV0FQU2taJrxNIdJvFFoPTF\nIL2x3lPPfGfYIEjp8QvENgkvaoWg+Of9fDBwXFpWVqVTdZHH+cKg4pejXwxU8RcY\noF3F3NyurzeWtR1mKsYuDZIfNN2007vJcDlrkUqEXr85YK72YGpOLZnK4DV6t+YP\n0pAApctGOBW0DU6E+1XSRPDwIAx+cGoudsmhOauRxpGclYoOPmOO4I0IyFMJS2q6\noAqLV/60/GpXUSxNpgB9fUtEzk7CxS/mt86dbpesYQKBgQDdyc+fh6+icarhlrzF\naA70gzwilWdusiBDHfhPCrqWhBRB8EQQ2KmTVo/9nRqfh2CzLSsVamCxKgwrhiIF\ndIQ52cgs9cwiPdzc3PGLnqfOa248+FhS95oNqinPkWSA0/0EOJeSVfvMdAgKTooc\nysU11vHLmWHpKIqcNjfWDGbHpwKBgQDQijZipEDg+rH/W+v7FYrW138+8rAIIMwe\n3UqPKRfe4tl6q2syOjhbpo1M1OjIh4mwM+UiGyfy0GFu/ZtQEjzmC+PP3Gs7K3ya\nJQ1wAhUlI5Zs3Q4jZrXHHS0eAiDEuzKVK6rKInhJ1FfnJtWMECSc9OK+ATS/QTiF\n/ocnKyh03QKBgQCtt1iMV7bVwbpan7qT1IGCOxhq7iLprVNfvqWzI3AqXKGRVCO8\nHjgUU4TM3LTxpxOyw/ou9/dsTMbjgFg9dZnrxgzoSk3ttA6+X8BB368IG1VpJAvq\nUE21zkaZcgQKdACFwd3WnMpwxaFWkVXUX25AUW9qTWVHPp3y5PSvD1+hmQKBgBKC\nggtFWwDdH5lz1kFGCznAjOnQbrF5/8Qpjimg0x6UcgtCVdRyeHgiE16jczoBVcZP\nBOJ/GI+j0VIhrnxv8fnVSlYz0UzCMmAYM9YiSTAvtXVaNZwMzMusmkmUlMYBe57j\n7lfcsWKUN20r9D5nXGiWD94fi0gCiPrTublPSlr9AoGBAJiSJMaEvA3/W9MbGdGK\nq35xBKAPa8g13e0JZOp9bF77wIDbZUhtHGbpLSpM9Q/YFganmB801uAm3DJN45Ug\nAgPTgQwUGeYTqdCwT4r83XJ7MjxlM/GfaZsLL41t8JuUuFN+aSuZaFCS6qIFL4BO\ng1FqmkG81CQTj0KYxFwYav9/\n-----END PRIVATE KEY-----\n";

    #[tokio::test]
    async fn vmess_aead_header_round_trips() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let destination = Destination::tcp(DestinationHost::parse("example.com").unwrap(), 443);
        let (header, _session) = build_vmess_request(&id, &destination).unwrap();
        let mut stream = &header[..];
        let (request, parsed_id) = read_vmess_request(&mut stream, &[id], None).await.unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(request.destination.host.to_string(), "example.com");
        assert_eq!(request.destination.port, 443);
        assert_eq!(
            request.options & VMESS_OPTION_CHUNK_MASKING,
            VMESS_OPTION_CHUNK_MASKING
        );
    }

    #[tokio::test]
    async fn rejects_replayed_vmess_auth_id() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let destination = Destination::tcp(DestinationHost::parse("example.com").unwrap(), 443);
        let (header, _session) = build_vmess_request(&id, &destination).unwrap();
        let replay_cache = VmessReplayCache::default();
        let mut first = &header[..];
        read_vmess_request(&mut first, &[id], Some(&replay_cache))
            .await
            .unwrap();
        let mut second = &header[..];
        assert!(matches!(
            read_vmess_request(&mut second, &[id], Some(&replay_cache)).await,
            Err(CoreError::VmessReplay)
        ));
    }

    #[tokio::test]
    async fn rejects_vmess_response_auth_mismatch() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let destination = Destination::tcp(DestinationHost::parse("example.com").unwrap(), 443);
        let (_header, session) = build_vmess_request(&id, &destination).unwrap();
        let mut server_session = session.clone();
        server_session.writer.iv = session.reader.iv;
        let (mut client, mut server) = duplex(1024);
        write_vmess_response_header(&mut server, &server_session, session.response_auth ^ 0xff)
            .await
            .unwrap();
        assert!(matches!(
            read_vmess_response_header(&mut client, &session).await,
            Err(CoreError::MalformedVmessRequest)
        ));
    }

    #[tokio::test]
    async fn vmess_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_vmess_proxy(id).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), echo_port);
        let (header, mut session) =
            build_vmess_request(&Uuid::parse_str(id).unwrap(), &destination).unwrap();
        client.write_all(&header).await.unwrap();
        read_vmess_response_header(&mut client, &session)
            .await
            .unwrap();
        session
            .writer
            .write_chunk(&mut client, b"vmin")
            .await
            .unwrap();
        let echoed = session
            .reader
            .read_chunk(&mut client)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"vmin");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_vmess_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vmess_upstream(echo_port, id).await;
        let outbound = vmess_outbound("upstream", upstream_port, id);
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vmou")
            .await;
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_tls_vmess_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_tls_vmess_upstream(echo_port, id).await;
        let outbound = tls_vmess_outbound("upstream", upstream_port, id);
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vmtl")
            .await;
    }

    #[tokio::test]
    async fn shadowsocks_framing_round_trips_chunks() {
        let key = shadowsocks_password_key("secret");
        let salt = [7_u8; SHADOWSOCKS_SALT_LEN];
        let mut writer = ShadowsocksWriter::new(key, salt).unwrap();
        let mut reader = ShadowsocksReader::new(key, Some(salt)).unwrap();
        let (mut client, mut server) = duplex(1024);

        writer.write_chunk(&mut client, b"hello").await.unwrap();
        let plain = reader.read_chunk(&mut server).await.unwrap().unwrap();
        assert_eq!(plain, b"hello");
    }

    async fn assert_socks5_inbound_reaches_echo_server_through_outbound(
        echo_port: u16,
        outbound: OutboundConfig,
        payload: &[u8],
    ) {
        let (proxy_port, task) = start_proxy_with_outbound(
            InboundConfig {
                tag: "test-in".to_owned(),
                listen: Some("127.0.0.1".parse().unwrap()),
                port: 0,
                protocol: InboundProtocol::Socks,
                settings: None,
                stream_settings: None,
                sniffing: None,
                allocate: None,
            },
            outbound,
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        task.abort();
    }

    #[tokio::test]
    async fn shadowsocks_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let (proxy_port, _task) = start_shadowsocks_proxy("secret").await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut session = start_shadowsocks_client(&mut client, "secret").await;
        let mut payload = encode_shadowsocks_address(&Destination::tcp(
            DestinationHost::parse("127.0.0.1").unwrap(),
            echo_port,
        ))
        .unwrap();
        payload.extend_from_slice(b"ssin");
        session
            .writer
            .write_chunk(&mut client, &payload)
            .await
            .unwrap();
        let echoed = session
            .reader
            .read_chunk(&mut client)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"ssin");
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_shadowsocks_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_shadowsocks_upstream(echo_port).await;
        let outbound = shadowsocks_outbound("upstream", upstream_port, "secret");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"ssou")
            .await;
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_tls_shadowsocks_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_tls_shadowsocks_upstream(echo_port).await;
        let outbound = tls_shadowsocks_outbound("upstream", upstream_port, "secret");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"sstl")
            .await;
    }

    #[tokio::test]
    async fn bind_inbound_reports_port_conflicts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let inbound = InboundConfig {
            tag: "conflict".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port,
            protocol: InboundProtocol::Socks,
            settings: None,
            stream_settings: None,
            sniffing: None,
            allocate: None,
        };

        let result = bind_inbound(inbound).await;
        assert!(matches!(result, Err(CoreError::Io(_))));
    }

    #[tokio::test]
    async fn accepts_socks5_domain_connect() {
        let (mut client, mut server) = duplex(1024);
        let inbound = test_inbound(InboundProtocol::Socks);
        let task = tokio::spawn(async move { accept_socks5(&mut server, &inbound).await.unwrap() });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
    }

    #[tokio::test]
    async fn accepts_socks5_password_auth() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Socks, "user", "pass");
        let task = tokio::spawn(async move { accept_socks5(&mut server, &inbound).await.unwrap() });

        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        client
            .write_all(&[0x01, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
            .await
            .unwrap();
        let mut auth_response = [0_u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [0x01, 0x00]);

        write_socks_connect(&mut client, "example.com", 443).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
    }

    #[tokio::test]
    async fn rejects_socks5_wrong_password() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Socks, "user", "pass");
        let task = tokio::spawn(async move { accept_socks5(&mut server, &inbound).await });

        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        client
            .write_all(&[
                0x01, 4, b'u', b's', b'e', b'r', 5, b'w', b'r', b'o', b'n', b'g',
            ])
            .await
            .unwrap();
        let mut auth_response = [0_u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [0x01, 0x01]);
        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::ProxyAuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn rejects_socks5_when_no_auth_is_not_offered() {
        let (mut client, mut server) = duplex(1024);
        let inbound = test_inbound(InboundProtocol::Socks);
        let task = tokio::spawn(async move { accept_socks5(&mut server, &inbound).await });

        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0xff]);
        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::UnsupportedSocksMethod)
        ));
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Socks, Vec::new()).await;
        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_rejects_tls_freedom_outbound() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            settings: None,
            stream_settings: Some(xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig {
                    server_name: Some("localhost".to_owned()),
                    allow_insecure: true,
                    alpn: vec!["h2".to_owned()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mux: None,
        };
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };

        assert!(matches!(
            send_socks_udp_payload(&outbound, &destination, b"ping").await,
            Err(CoreError::UnsupportedSocksUdpOutbound(tag)) if tag == "direct"
        ));
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_shadowsocks() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let shadowsocks_port = start_shadowsocks_udp_upstream("secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![shadowsocks_outbound("direct", shadowsocks_port, "secret")],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_rejects_tls_shadowsocks_upstream() {
        let outbound = tls_shadowsocks_outbound("direct", 9, "secret");
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };

        assert!(matches!(
            send_socks_udp_payload(&outbound, &destination, b"ping").await,
            Err(CoreError::UnsupportedSocksUdpOutbound(tag)) if tag == "direct"
        ));
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_socks_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let socks_port = start_socks_udp_upstream().await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![socks_outbound("direct", socks_port, None, None)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_rejects_tls_socks_upstream() {
        let outbound = tls_socks_outbound("direct", 9, None, None);
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };

        assert!(matches!(
            send_socks_udp_payload(&outbound, &destination, b"ping").await,
            Err(CoreError::UnsupportedSocksUdpOutbound(tag)) if tag == "direct"
        ));
    }

    async fn assert_socks_udp_round_trip(proxy_port: u16, upstream_port: u16) {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        tcp.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = [0_u8; 10];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(response[..4], [0x05, 0x00, 0x00, 0x01]);
        let udp_port = u16::from_be_bytes([response[8], response[9]]);

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let packet = encode_socks_udp_packet(&destination, b"ping").unwrap();
        udp.send_to(&packet, ("127.0.0.1", udp_port)).await.unwrap();
        let mut buffer = [0_u8; 128];
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.payload, b"pong");
    }

    #[tokio::test]
    async fn shadowsocks_udp_uses_response_destination() {
        let request_destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };
        let response_destination = Destination {
            host: DestinationHost::parse("198.51.100.7").unwrap(),
            port: 5353,
            network: Network::Udp,
        };
        let key = shadowsocks_password_key("secret");
        let request = encrypt_shadowsocks_udp_packet(key, &request_destination, b"ping").unwrap();
        let (parsed_request_destination, parsed_request_payload) =
            decrypt_shadowsocks_udp_packet(key, &request).unwrap();
        assert_eq!(parsed_request_destination, request_destination);
        assert_eq!(parsed_request_payload, b"ping");

        let response = encrypt_shadowsocks_udp_packet(key, &response_destination, b"pong").unwrap();
        let (parsed_response_destination, parsed_response_payload) =
            decrypt_shadowsocks_udp_packet(key, &response).unwrap();
        assert_eq!(parsed_response_destination, response_destination);
        assert_eq!(parsed_response_payload, b"pong");
    }

    #[tokio::test]
    async fn shadowsocks_udp_inbound_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_shadowsocks_udp_proxy("secret").await;
        assert_shadowsocks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn shadowsocks_udp_inbound_drops_malformed_packets_without_stopping() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_shadowsocks_udp_proxy("secret").await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"not shadowsocks", ("127.0.0.1", proxy_port))
            .await
            .unwrap();
        assert_shadowsocks_udp_round_trip_with_client(&client, proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    async fn assert_shadowsocks_udp_round_trip(proxy_port: u16, upstream_port: u16) {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_shadowsocks_udp_round_trip_with_client(&client, proxy_port, upstream_port).await;
    }

    async fn assert_shadowsocks_udp_round_trip_with_client(
        client: &UdpSocket,
        proxy_port: u16,
        upstream_port: u16,
    ) {
        let key = shadowsocks_password_key("secret");
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let request = encrypt_shadowsocks_udp_packet(key, &destination, b"ping").unwrap();
        client
            .send_to(&request, ("127.0.0.1", proxy_port))
            .await
            .unwrap();

        let mut response = [0_u8; 65535];
        let response_length = timeout(DNS_TIMEOUT, client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (response_destination, response_payload) =
            decrypt_shadowsocks_udp_packet(key, &response[..response_length]).unwrap();
        assert_eq!(response_destination, destination);
        assert_eq!(response_payload, b"pong");
    }

    #[tokio::test]
    async fn accepts_http_connect() {
        let (mut client, mut server) = duplex(1024);
        let inbound = test_inbound(InboundProtocol::Http);
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert!(accepted.remote_prefix.is_empty());
    }

    #[tokio::test]
    async fn accepts_http_basic_proxy_auth() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Http, "user", "pass");
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
    }

    #[tokio::test]
    async fn rejects_http_missing_proxy_auth() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Http, "user", "pass");
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await });

        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = vec![0_u8; 92];
        client.read_exact(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::ProxyAuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn rejects_incomplete_http_connect_header_at_limit() {
        let (mut client, mut server) = duplex(8192);
        let inbound = test_inbound(InboundProtocol::Http);
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await });
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        request.resize(8192, b'a');
        client.write_all(&request).await.unwrap();

        let result = task.await.unwrap();
        assert!(matches!(result, Err(CoreError::HttpHeaderTooLarge)));
    }

    #[tokio::test]
    async fn accepts_http_absolute_form_request() {
        let (mut client, mut server) = duplex(1024);
        let inbound = test_inbound(InboundProtocol::Http);
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(
                b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
            )
            .await
            .unwrap();

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 8080);
        assert!(
            accepted
                .remote_prefix
                .starts_with(b"GET /path?q=1 HTTP/1.1\r\n")
        );
    }

    #[tokio::test]
    async fn accepts_trojan_domain_connect() {
        let (mut client, mut server) = duplex(1024);
        let inbound = trojan_inbound("secret");
        let task = tokio::spawn(async move { accept_trojan(&mut server, &inbound).await.unwrap() });

        write_trojan_connect(&mut client, "secret", "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert!(accepted.remote_prefix.is_empty());
    }

    #[tokio::test]
    async fn rejects_trojan_wrong_password() {
        let (mut client, mut server) = duplex(1024);
        let inbound = trojan_inbound("secret");
        let task = tokio::spawn(async move { accept_trojan(&mut server, &inbound).await });

        write_trojan_connect(&mut client, "wrong", "example.com", 443).await;

        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::InvalidTrojanPassword)
        ));
    }

    #[tokio::test]
    async fn accepts_vless_domain_connect() {
        let (mut client, mut server) = duplex(1024);
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let inbound = vless_inbound(id);
        let task = tokio::spawn(async move { accept_vless(&mut server, &inbound).await.unwrap() });

        write_vless_connect(&mut client, id, "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert!(accepted.remote_prefix.is_empty());
        assert_eq!(accepted.client_prefix, [0, 0]);
    }

    #[tokio::test]
    async fn rejects_vless_wrong_client_id() {
        let (mut client, mut server) = duplex(1024);
        let inbound = vless_inbound("01234567-89ab-cdef-0123-456789abcdef");
        let task = tokio::spawn(async move { accept_vless(&mut server, &inbound).await });

        write_vless_connect(
            &mut client,
            "11111111-1111-1111-1111-111111111111",
            "example.com",
            443,
        )
        .await;

        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::InvalidVlessClient)
        ));
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Socks, Vec::new()).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn trojan_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_trojan_proxy("secret").await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_trojan_connect(&mut client, "secret", "127.0.0.1", echo_port).await;
        client.write_all(b"trog").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"trog");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn vless_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_vless_proxy(id).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_vless_connect(&mut client, id, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 0]);

        client.write_all(b"vles").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"vles");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn freedom_redirect_reaches_configured_target() {
        let requested_port = start_echo_server().await;
        let redirected_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_proxy_with_freedom_redirect(redirected_port).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", requested_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"rdir").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"rdir");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_reaches_tls_echo_server_through_freedom() {
        let echo_port = start_tls_echo_server().await;
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            settings: None,
            stream_settings: Some(xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig {
                    server_name: Some("localhost".to_owned()),
                    allow_insecure: true,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mux: None,
        };
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![outbound],
        )
        .await;
        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"tls!").await;
        proxy_task.abort();
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[tokio::test]
    async fn freedom_tls_alpn_negotiates_with_server_when_backend_supports_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = test_tls_acceptor_with_alpn(&["h2"]);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            stream.get_ref().negotiated_alpn().unwrap()
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            settings: None,
            stream_settings: Some(xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig {
                    server_name: Some("localhost".to_owned()),
                    allow_insecure: true,
                    alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mux: None,
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let stream = connect_freedom(&outbound, &destination).await.unwrap();
        match stream {
            OutboundStream::Tls(stream) => {
                let selected = stream.get_ref().negotiated_alpn().unwrap();
                assert_eq!(selected, Some(b"h2".to_vec()));
            }
            OutboundStream::Tcp(_) => panic!("expected TLS stream"),
        }
        let selected = server.await.unwrap();
        assert_eq!(selected, Some(b"h2".to_vec()));
    }

    #[tokio::test]
    async fn freedom_tls_to_ip_without_server_name_fails_before_connecting() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            settings: None,
            stream_settings: Some(xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig::default()),
                ..Default::default()
            }),
            mux: None,
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), 9);

        assert!(matches!(
            connect_freedom(&outbound, &destination).await,
            Err(CoreError::MissingTlsServerName)
        ));
    }

    #[tokio::test]
    async fn http_connect_inbound_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Http, Vec::new()).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"pong").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn http_absolute_form_inbound_reaches_http_server_through_freedom() {
        let (http_port, request_task) = start_http_server().await;
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Http, Vec::new()).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{http_port}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert_eq!(request_task.await.unwrap(), "GET /path?q=1 HTTP/1.1");
        assert!(String::from_utf8_lossy(&response).contains("ok"));
        proxy_task.abort();
    }

    #[tokio::test]
    async fn ip_if_non_match_resolves_domain_for_ip_rules() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy_with_domain_strategy(
            InboundProtocol::Socks,
            Some("IPIfNonMatch".to_owned()),
            vec![rule],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "localhost", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn source_route_closes_blocked_connections() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["127.0.0.1".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Socks, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn source_port_route_closes_blocked_connections() {
        let echo_port = start_echo_server().await;
        let client_socket = TcpSocket::new_v4().unwrap();
        client_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source_port = client_socket.local_addr().unwrap().port();
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: Vec::new(),
            source_port: Some(source_port.into()),
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Socks, vec![rule]).await;
        let proxy_addr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
        let mut client = client_socket.connect(proxy_addr).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn blackhole_route_closes_blocked_connections() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy(InboundProtocol::Socks, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn blackhole_http_response_returns_forbidden() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_proxy_with_blackhole_response(vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut socks_response = [0_u8; 10];
        client.read_exact(&mut socks_response).await.unwrap();
        assert_eq!(socks_response[1], 0x00);

        let mut http_response = Vec::new();
        client.read_to_end(&mut http_response).await.unwrap();
        assert_eq!(
            http_response,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_door_inbound_reaches_configured_target() {
        let echo_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_dokodemo_proxy(echo_port).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(b"door").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"door");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_door_inbound_bridges_dns_outbound_to_udp() {
        let (dns_port, dns_task) = start_udp_dns_server(vec![0x12, 0x34, 0x81, 0x80]).await;
        let (proxy_port, proxy_task) = start_dns_proxy(dns_port).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0, 3, 0x12, 0x34, 0x01]).await.unwrap();
        let mut length = [0_u8; 2];
        client.read_exact(&mut length).await.unwrap();
        let response_length = u16::from_be_bytes(length) as usize;
        let mut response = vec![0_u8; response_length];
        client.read_exact(&mut response).await.unwrap();
        let mut closed = [0_u8; 1];
        assert_eq!(client.read(&mut closed).await.unwrap(), 0);

        assert_eq!(dns_task.await.unwrap(), vec![0x12, 0x34, 0x01]);
        assert_eq!(response, vec![0x12, 0x34, 0x81, 0x80]);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn dns_outbound_rejects_zero_length_request() {
        let (dns_port, dns_task) = start_udp_dns_server(vec![0x12, 0x34]).await;
        let (proxy_port, proxy_task) = start_dns_proxy(dns_port).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0, 0]).await.unwrap();
        let mut closed = [0_u8; 1];
        assert_eq!(client.read(&mut closed).await.unwrap(), 0);

        proxy_task.abort();
        dns_task.abort();
    }

    #[tokio::test]
    async fn tls_socks_inbound_terminates_before_parsing() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-core-inbound-cert.pem");
        let key = dir.join("xrs-core-inbound-key.pem");
        std::fs::write(&cert, TEST_TLS_CERT).unwrap();
        std::fs::write(&key, TEST_TLS_KEY).unwrap();
        let echo_port = start_echo_server().await;
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            settings: None,
            stream_settings: None,
            mux: None,
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(xrs_config::StreamSettingsConfig {
            network: Some("tcp".to_owned()),
            security: Some("tls".to_owned()),
            tls_settings: Some(xrs_config::TlsSettingsConfig {
                certificates: vec![xrs_config::TlsCertificateConfig {
                    certificate_file: Some(cert),
                    key_file: Some(key),
                    extra: std::collections::BTreeMap::new(),
                }],
                ..xrs_config::TlsSettingsConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        });
        let (proxy_port, proxy_task) = start_proxy_with_outbound(inbound, outbound).await;

        let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let mut client = connector.connect("localhost", tcp).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"tls!").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tls!");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_socks_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_socks_upstream(echo_port).await;
        let (proxy_port, proxy_task) =
            start_upstream_proxy(OutboundProtocol::Socks, upstream_port).await;
        assert_socks_client_echo(proxy_port, "example.com", echo_port, b"sock").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_http_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_http_upstream(echo_port).await;
        let (proxy_port, proxy_task) =
            start_upstream_proxy(OutboundProtocol::Http, upstream_port).await;
        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"http").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_tls_socks_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_tls_socks_upstream(echo_port).await;
        let (proxy_port, proxy_task) =
            start_tls_upstream_proxy(OutboundProtocol::Socks, upstream_port).await;
        assert_socks_client_echo(proxy_port, "localhost", echo_port, b"sock").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_tls_http_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_tls_http_upstream(echo_port).await;
        let (proxy_port, proxy_task) =
            start_tls_upstream_proxy(OutboundProtocol::Http, upstream_port).await;
        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"http").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_authenticates_to_socks_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_socks_auth_upstream(echo_port, "alice", "secret").await;
        let (proxy_port, proxy_task) = start_authenticated_upstream_proxy(
            OutboundProtocol::Socks,
            upstream_port,
            "alice",
            "secret",
        )
        .await;
        assert_socks_client_echo(proxy_port, "example.com", echo_port, b"sock").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_authenticates_to_http_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_http_auth_upstream(echo_port, "alice", "secret").await;
        let (proxy_port, proxy_task) = start_authenticated_upstream_proxy(
            OutboundProtocol::Http,
            upstream_port,
            "alice",
            "secret",
        )
        .await;
        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"http").await;
        proxy_task.abort();
    }

    async fn assert_socks_client_echo(proxy_port: u16, host: &str, port: u16, payload: &[u8]) {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, host, port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn rejects_socks_upstream_domain_longer_than_protocol_limit() {
        let (mut client, mut upstream) = duplex(1024);
        let destination = Destination::tcp(DestinationHost::Domain("a".repeat(256)), 443);
        let server = xrs_config::ProxyServerConfig {
            address: "127.0.0.1".to_owned(),
            port: 1080,
            user: None,
            method: None,
            password: None,
            id: None,
            security: None,
            extra: std::collections::BTreeMap::new(),
        };
        let task = tokio::spawn(async move {
            connect_socks_upstream(&mut upstream, &server, &destination).await
        });

        client.read_exact(&mut [0_u8; 3]).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::SocksDomainTooLong)
        ));
    }

    #[tokio::test]
    async fn times_out_http_upstream_that_stalls_after_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let (proxy_port, proxy_task) =
            start_upstream_proxy(OutboundProtocol::Http, upstream_port).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", 443).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        let mut closed = [0_u8; 1];
        let read = timeout(Duration::from_secs(10), client.read(&mut closed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
        upstream_task.abort();
    }

    async fn write_trojan_connect<S>(stream: &mut S, password: &str, host: &str, port: u16)
    where
        S: AsyncWrite + Unpin,
    {
        stream
            .write_all(&trojan_password_hash(password))
            .await
            .unwrap();
        stream.write_all(b"\r\n\x01\x03").await.unwrap();
        stream.write_all(&[host.len() as u8]).await.unwrap();
        stream.write_all(host.as_bytes()).await.unwrap();
        stream.write_all(&port.to_be_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
    }

    async fn write_vless_connect<S>(stream: &mut S, id: &str, host: &str, port: u16)
    where
        S: AsyncWrite + Unpin,
    {
        let id = Uuid::parse_str(id).unwrap();
        stream.write_all(&[0]).await.unwrap();
        stream.write_all(id.as_bytes()).await.unwrap();
        stream.write_all(&[0, 0x01]).await.unwrap();
        stream.write_all(&port.to_be_bytes()).await.unwrap();
        stream.write_all(&[0x02, host.len() as u8]).await.unwrap();
        stream.write_all(host.as_bytes()).await.unwrap();
    }

    async fn start_shadowsocks_client(
        stream: &mut TcpStream,
        password: &str,
    ) -> ShadowsocksSession {
        let key = shadowsocks_password_key(password);
        let mut write_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
        OsRng.fill_bytes(&mut write_salt);
        stream.write_all(&write_salt).await.unwrap();
        let mut read_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
        stream.read_exact(&mut read_salt).await.unwrap();
        ShadowsocksSession::new(key, read_salt, write_salt).unwrap()
    }

    async fn start_shadowsocks_proxy(password: &str) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(shadowsocks_inbound(password), Vec::new()).await
    }

    async fn start_shadowsocks_udp_proxy(password: &str) -> (u16, tokio::task::JoinHandle<()>) {
        let inbound = shadowsocks_udp_inbound(password);
        let socket = bind_udp_inbound(&inbound).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_owned(),
                protocol: OutboundProtocol::Freedom,
                settings: None,
                stream_settings: None,
                mux: None,
            }],
            routing: xrs_config::RoutingConfig {
                rules: Vec::new(),
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
            },
            ..RootConfig::default()
        };
        let router = Arc::new(Router::from_config(&config).unwrap());
        let outbounds = Arc::new(
            config
                .outbounds
                .iter()
                .map(|outbound| (outbound.tag.clone(), outbound.clone()))
                .collect::<HashMap<_, _>>(),
        );
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_shadowsocks_udp_inbound(inbound, socket, router, outbounds, counters)
                .await
                .unwrap();
        });
        (port, task)
    }

    fn shadowsocks_inbound(password: &str) -> InboundConfig {
        shadowsocks_inbound_with_network(password, "tcp")
    }

    fn shadowsocks_udp_inbound(password: &str) -> InboundConfig {
        shadowsocks_inbound_with_network(password, "udp")
    }

    fn shadowsocks_inbound_with_network(password: &str, network: &str) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::Shadowsocks,
            settings: Some(xrs_config::InboundSettings {
                address: None,
                port: None,
                clients: Vec::new(),
                accounts: Vec::new(),
                method: Some(SHADOWSOCKS_METHOD.to_owned()),
                password: Some(password.to_owned()),
                network: Some(network.to_owned()),
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
        }
    }

    async fn start_vmess_proxy(id: &str) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(vmess_inbound(id), Vec::new()).await
    }

    fn vmess_inbound(id: &str) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::Vmess,
            settings: Some(xrs_config::InboundSettings {
                address: None,
                port: None,
                clients: vec![xrs_config::InboundClientConfig {
                    id: Some(id.to_owned()),
                    password: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                method: None,
                password: None,
                network: Some("tcp".to_owned()),
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
        }
    }

    fn vmess_outbound(tag: &str, port: u16, id: &str) -> OutboundConfig {
        let mut outbound = vmess_outbound_with_tls(tag, port, id, false);
        outbound.stream_settings = None;
        outbound
    }

    fn tls_vmess_outbound(tag: &str, port: u16, id: &str) -> OutboundConfig {
        vmess_outbound_with_tls(tag, port, id, true)
    }

    fn vmess_outbound_with_tls(tag: &str, port: u16, id: &str, use_tls: bool) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Vmess,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: None,
                    password: None,
                    id: Some(id.to_owned()),
                    security: Some("none".to_owned()),
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
        }
    }

    fn shadowsocks_outbound(tag: &str, port: u16, password: &str) -> OutboundConfig {
        let mut outbound = shadowsocks_outbound_with_tls(tag, port, password, false);
        outbound.stream_settings = None;
        outbound
    }

    fn tls_shadowsocks_outbound(tag: &str, port: u16, password: &str) -> OutboundConfig {
        shadowsocks_outbound_with_tls(tag, port, password, true)
    }

    fn shadowsocks_outbound_with_tls(
        tag: &str,
        port: u16,
        password: &str,
        use_tls: bool,
    ) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Shadowsocks,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: Some(SHADOWSOCKS_METHOD.to_owned()),
                    password: Some(password.to_owned()),
                    id: None,
                    security: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
        }
    }

    fn tls_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            security: Some("tls".to_owned()),
            tls_settings: Some(xrs_config::TlsSettingsConfig {
                server_name: Some("localhost".to_owned()),
                allow_insecure: true,
                ..xrs_config::TlsSettingsConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn socks_outbound(
        tag: &str,
        port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> OutboundConfig {
        let mut outbound = socks_outbound_with_tls(tag, port, user, password, false);
        outbound.stream_settings = None;
        outbound
    }

    fn tls_socks_outbound(
        tag: &str,
        port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> OutboundConfig {
        socks_outbound_with_tls(tag, port, user, password, true)
    }

    fn socks_outbound_with_tls(
        tag: &str,
        port: u16,
        user: Option<&str>,
        password: Option<&str>,
        use_tls: bool,
    ) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Socks,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: user.map(str::to_owned),
                    method: None,
                    password: password.map(str::to_owned),
                    id: None,
                    security: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
        }
    }

    async fn start_proxy_with_outbound(
        inbound: InboundConfig,
        outbound: OutboundConfig,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let (inbound, listener) = bind_inbound(inbound).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds: vec![outbound.clone()],
            routing: xrs_config::RoutingConfig {
                rules: Vec::new(),
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
            },
            ..RootConfig::default()
        };
        let router = Arc::new(Router::from_config(&config).unwrap());
        let outbounds = Arc::new(HashMap::from([(outbound.tag.clone(), outbound)]));
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_inbound(
                inbound,
                listener,
                router,
                outbounds,
                counters,
                Arc::new(VmessReplayCache::default()),
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn start_shadowsocks_upstream(target_port: u16) -> u16 {
        start_shadowsocks_upstream_with_tls(target_port, false).await
    }

    async fn start_tls_shadowsocks_upstream(target_port: u16) -> u16 {
        start_shadowsocks_upstream_with_tls(target_port, true).await
    }

    async fn start_shadowsocks_upstream_with_tls(target_port: u16, use_tls: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = if use_tls {
                OutboundStream::Tls(acceptor.accept(stream).await.unwrap())
            } else {
                OutboundStream::Tcp(stream)
            };
            let key = shadowsocks_password_key("secret");
            let mut read_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
            stream.read_exact(&mut read_salt).await.unwrap();
            let mut write_salt = [0_u8; SHADOWSOCKS_SALT_LEN];
            OsRng.fill_bytes(&mut write_salt);
            let mut session = ShadowsocksSession::new(key, read_salt, write_salt).unwrap();
            let first = session
                .reader
                .read_chunk(&mut stream)
                .await
                .unwrap()
                .unwrap();
            let (_destination, offset) = parse_shadowsocks_address(&first).unwrap();
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            if offset < first.len() {
                remote.write_all(&first[offset..]).await.unwrap();
            } else if let Some(chunk) = session.reader.read_chunk(&mut stream).await.unwrap() {
                remote.write_all(&chunk).await.unwrap();
            }
            let mut response = [0_u8; 4];
            remote.read_exact(&mut response).await.unwrap();
            stream.write_all(&write_salt).await.unwrap();
            session
                .writer
                .write_chunk(&mut stream, &response)
                .await
                .unwrap();
        });
        port
    }

    async fn start_vmess_upstream(target_port: u16, id: &str) -> u16 {
        start_vmess_upstream_with_tls(target_port, id, false).await
    }

    async fn start_tls_vmess_upstream(target_port: u16, id: &str) -> u16 {
        start_vmess_upstream_with_tls(target_port, id, true).await
    }

    async fn start_vmess_upstream_with_tls(target_port: u16, id: &str, use_tls: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = Uuid::parse_str(id).unwrap();
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = if use_tls {
                OutboundStream::Tls(acceptor.accept(stream).await.unwrap())
            } else {
                OutboundStream::Tcp(stream)
            };
            let (request, _) = read_vmess_request(&mut stream, &[id], None).await.unwrap();
            assert_eq!(request.destination.port, target_port);
            let response_iv = vmess_response_derive(&request.body_iv);
            let session = VmessSession {
                reader: VmessReader {
                    iv: request.body_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                },
                writer: VmessWriter {
                    iv: response_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                },
                response_auth: request.response_auth,
            };
            write_vmess_response_header(&mut stream, &session, request.response_auth)
                .await
                .unwrap();
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            let first = session
                .reader
                .clone()
                .read_chunk(&mut stream)
                .await
                .unwrap()
                .unwrap();
            remote.write_all(&first).await.unwrap();
            let mut response = [0_u8; 4];
            remote.read_exact(&mut response).await.unwrap();
            let mut writer = session.writer;
            writer.write_chunk(&mut stream, &response).await.unwrap();
            writer.write_end(&mut stream).await.unwrap();
        });
        port
    }

    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        port
    }

    async fn start_tls_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        port
    }

    fn test_tls_acceptor() -> tokio_native_tls::TlsAcceptor {
        test_tls_acceptor_with_alpn(&[])
    }

    fn test_tls_acceptor_with_alpn(protocols: &[&str]) -> tokio_native_tls::TlsAcceptor {
        let identity =
            native_tls::Identity::from_pkcs8(TEST_TLS_CERT.as_bytes(), TEST_TLS_KEY.as_bytes())
                .unwrap();
        let mut builder = native_tls::TlsAcceptor::builder(identity);
        if !protocols.is_empty() {
            builder.accept_alpn(protocols);
        }
        tokio_native_tls::TlsAcceptor::from(builder.build().unwrap())
    }

    async fn start_http_server() -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_header(&mut stream).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap()
                .to_owned()
        });
        (port, task)
    }

    async fn start_test_proxy(
        protocol: InboundProtocol,
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(test_inbound(protocol), rules).await
    }

    fn test_inbound(protocol: InboundProtocol) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol,
            settings: None,
            stream_settings: None,
            sniffing: None,
            allocate: None,
        }
    }

    fn auth_inbound(protocol: InboundProtocol, user: &str, pass: &str) -> InboundConfig {
        let mut inbound = test_inbound(protocol);
        inbound.settings = Some(xrs_config::InboundSettings {
            address: None,
            port: None,
            clients: Vec::new(),
            accounts: vec![xrs_config::InboundAccountConfig {
                user: user.to_owned(),
                pass: pass.to_owned(),
                extra: std::collections::BTreeMap::new(),
            }],
            method: None,
            password: None,
            network: None,
            extra: std::collections::BTreeMap::new(),
        });
        inbound
    }

    async fn start_trojan_proxy(password: &str) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(trojan_inbound(password), Vec::new()).await
    }

    async fn start_vless_proxy(id: &str) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(vless_inbound(id), Vec::new()).await
    }

    fn trojan_inbound(password: &str) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::Trojan,
            settings: Some(xrs_config::InboundSettings {
                address: None,
                port: None,
                clients: vec![xrs_config::InboundClientConfig {
                    id: None,
                    password: Some(password.to_owned()),
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                method: None,
                password: None,
                network: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
        }
    }

    fn vless_inbound(id: &str) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::Vless,
            settings: Some(xrs_config::InboundSettings {
                address: None,
                port: None,
                clients: vec![xrs_config::InboundClientConfig {
                    id: Some(id.to_owned()),
                    password: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                method: None,
                password: None,
                network: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
        }
    }

    async fn start_dokodemo_proxy(target_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(
            InboundConfig {
                tag: "test-in".to_owned(),
                listen: Some("127.0.0.1".parse().unwrap()),
                port: 0,
                protocol: InboundProtocol::DokodemoDoor,
                settings: Some(xrs_config::InboundSettings {
                    address: Some("127.0.0.1".to_owned()),
                    port: Some(target_port),
                    clients: Vec::new(),
                    accounts: Vec::new(),
                    method: None,
                    password: None,
                    network: None,
                    extra: std::collections::BTreeMap::new(),
                }),
                stream_settings: None,
                sniffing: None,
                allocate: None,
            },
            Vec::new(),
        )
        .await
    }

    async fn start_dns_proxy(dns_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
        let inbound = InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::DokodemoDoor,
            settings: Some(xrs_config::InboundSettings {
                address: Some("1.1.1.1".to_owned()),
                port: Some(53),
                clients: Vec::new(),
                accounts: Vec::new(),
                method: None,
                password: None,
                network: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
        };
        let outbound = OutboundConfig {
            tag: "dns-out".to_owned(),
            protocol: OutboundProtocol::Dns,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port: dns_port,
                    user: None,
                    method: None,
                    password: None,
                    id: None,
                    security: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
        };
        let (inbound, listener) = bind_inbound(inbound).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds: vec![outbound.clone()],
            routing: xrs_config::RoutingConfig {
                rules: Vec::new(),
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
            },
            ..RootConfig::default()
        };
        let router = Arc::new(Router::from_config(&config).unwrap());
        let outbounds = Arc::new(HashMap::from([("dns-out".to_owned(), outbound)]));
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_inbound(
                inbound,
                listener,
                router,
                outbounds,
                counters,
                Arc::new(VmessReplayCache::default()),
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn start_udp_dns_server(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&response, peer).await.unwrap();
            buffer[..length].to_vec()
        });
        (port, task)
    }

    async fn start_shadowsocks_udp_upstream(password: &str) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let key = shadowsocks_password_key(password);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 65535];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let (destination, payload) =
                decrypt_shadowsocks_udp_packet(key, &buffer[..length]).unwrap();
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            upstream
                .connect((destination.host.to_string(), destination.port))
                .await
                .unwrap();
            upstream.send(&payload).await.unwrap();
            let mut response = [0_u8; 65535];
            let response_length = upstream.recv(&mut response).await.unwrap();
            let packet =
                encrypt_shadowsocks_udp_packet(key, &destination, &response[..response_length])
                    .unwrap();
            socket.send_to(&packet, peer).await.unwrap();
        });
        port
    }

    async fn start_upstream_proxy(
        protocol: OutboundProtocol,
        upstream_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_upstream_proxy_with_auth_and_tls(protocol, upstream_port, None, None, false).await
    }

    async fn start_tls_upstream_proxy(
        protocol: OutboundProtocol,
        upstream_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_upstream_proxy_with_auth_and_tls(protocol, upstream_port, None, None, true).await
    }

    async fn start_authenticated_upstream_proxy(
        protocol: OutboundProtocol,
        upstream_port: u16,
        user: &str,
        password: &str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_upstream_proxy_with_auth(protocol, upstream_port, Some(user), Some(password)).await
    }

    async fn start_upstream_proxy_with_auth(
        protocol: OutboundProtocol,
        upstream_port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_upstream_proxy_with_auth_and_tls(protocol, upstream_port, user, password, false).await
    }

    async fn start_upstream_proxy_with_auth_and_tls(
        protocol: OutboundProtocol,
        upstream_port: u16,
        user: Option<&str>,
        password: Option<&str>,
        use_tls: bool,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let (inbound, listener) = bind_inbound(InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::Socks,
            settings: None,
            stream_settings: None,
            sniffing: None,
            allocate: None,
        })
        .await
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        let outbound = OutboundConfig {
            tag: "upstream".to_owned(),
            protocol,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port: upstream_port,
                    user: user.map(str::to_owned),
                    method: None,
                    password: password.map(str::to_owned),
                    id: None,
                    security: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(|| xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig {
                    server_name: Some("localhost".to_owned()),
                    allow_insecure: true,
                    ..xrs_config::TlsSettingsConfig::default()
                }),
                ..xrs_config::StreamSettingsConfig::default()
            }),
            mux: None,
        };
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds: vec![outbound.clone()],
            routing: xrs_config::RoutingConfig {
                rules: Vec::new(),
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
            },
            ..RootConfig::default()
        };
        let router = Arc::new(Router::from_config(&config).unwrap());
        let outbounds = Arc::new(HashMap::from([("upstream".to_owned(), outbound)]));
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_inbound(
                inbound,
                listener,
                router,
                outbounds,
                counters,
                Arc::new(VmessReplayCache::default()),
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn start_socks_udp_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).await.unwrap();
            let request = accept_socks5_request(&mut control).await;
            assert_eq!(request.network, Network::Udp);
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_port = relay.local_addr().unwrap().port();
            control
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1])
                .await
                .unwrap();
            control.write_all(&relay_port.to_be_bytes()).await.unwrap();
            let mut packet = [0_u8; 65535];
            let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
            let parsed = parse_socks_udp_packet(&packet[..length]).unwrap();
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            upstream
                .connect((parsed.destination.host.to_string(), parsed.destination.port))
                .await
                .unwrap();
            upstream.send(&parsed.payload).await.unwrap();
            let mut response = [0_u8; 65535];
            let response_length = upstream.recv(&mut response).await.unwrap();
            let wrapped =
                encode_socks_udp_packet(&parsed.destination, &response[..response_length]).unwrap();
            relay.send_to(&wrapped, peer).await.unwrap();
            let mut closed = [0_u8; 1];
            let _ = control.read(&mut closed).await;
        });
        port
    }

    async fn start_socks_upstream(target_port: u16) -> u16 {
        start_socks_upstream_with_auth(target_port, None, None).await
    }

    async fn start_socks_auth_upstream(target_port: u16, user: &str, password: &str) -> u16 {
        start_socks_upstream_with_auth(target_port, Some(user), Some(password)).await
    }

    async fn start_socks_upstream_with_auth(
        target_port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> u16 {
        start_socks_upstream_with_auth_and_tls(target_port, user, password, false).await
    }

    async fn start_tls_socks_upstream(target_port: u16) -> u16 {
        start_socks_upstream_with_auth_and_tls(target_port, None, None, true).await
    }

    async fn start_socks_upstream_with_auth_and_tls(
        target_port: u16,
        user: Option<&str>,
        password: Option<&str>,
        use_tls: bool,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let user = user.map(str::to_owned);
        let password = password.map(str::to_owned);
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = if use_tls {
                OutboundStream::Tls(acceptor.accept(stream).await.unwrap())
            } else {
                OutboundStream::Tcp(stream)
            };
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            if let (Some(user), Some(password)) = (user.as_deref(), password.as_deref()) {
                assert_eq!(greeting, [0x05, 0x01, 0x02]);
                stream.write_all(&[0x05, 0x02]).await.unwrap();
                assert_socks_upstream_auth(&mut stream, user, password).await;
            } else {
                assert_eq!(greeting, [0x05, 0x01, 0x00]);
                stream.write_all(&[0x05, 0x00]).await.unwrap();
            }
            let destination = accept_socks5_request(&mut stream).await;
            assert_eq!(destination.network, Network::Tcp);
            assert_eq!(destination.port, target_port);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            io::copy_bidirectional(&mut stream, &mut remote)
                .await
                .unwrap();
        });
        port
    }

    async fn assert_socks_upstream_auth<S>(stream: &mut S, expected_user: &str, expected_pass: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x01);
        let mut user = vec![0_u8; usize::from(header[1])];
        stream.read_exact(&mut user).await.unwrap();
        let mut pass_len = [0_u8; 1];
        stream.read_exact(&mut pass_len).await.unwrap();
        let mut password = vec![0_u8; usize::from(pass_len[0])];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(user, expected_user.as_bytes());
        assert_eq!(password, expected_pass.as_bytes());
        stream.write_all(&[0x01, 0x00]).await.unwrap();
    }

    async fn accept_socks5_request<S>(stream: &mut S) -> Destination
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x05);
        assert_eq!(header[2], 0x00);
        let host = read_socks_host(stream, header[3]).await.unwrap();
        let port = read_port(stream).await.unwrap();
        let network = if header[1] == 0x03 {
            Network::Udp
        } else {
            Network::Tcp
        };
        Destination {
            host,
            port,
            network,
        }
    }

    async fn start_http_upstream(target_port: u16) -> u16 {
        start_http_upstream_with_auth(target_port, None, None).await
    }

    async fn start_http_auth_upstream(target_port: u16, user: &str, password: &str) -> u16 {
        start_http_upstream_with_auth(target_port, Some(user), Some(password)).await
    }

    async fn start_http_upstream_with_auth(
        target_port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> u16 {
        start_http_upstream_with_auth_and_tls(target_port, user, password, false).await
    }

    async fn start_tls_http_upstream(target_port: u16) -> u16 {
        start_http_upstream_with_auth_and_tls(target_port, None, None, true).await
    }

    async fn start_http_upstream_with_auth_and_tls(
        target_port: u16,
        user: Option<&str>,
        password: Option<&str>,
        use_tls: bool,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_auth = user.zip(password).map(|(user, password)| {
            format!(
                "Basic {}",
                encode_base64(format!("{user}:{password}").as_bytes())
            )
        });
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = if use_tls {
                OutboundStream::Tls(acceptor.accept(stream).await.unwrap())
            } else {
                OutboundStream::Tcp(stream)
            };
            let (destination, proxy_auth) = read_http_connect_request(&mut stream).await;
            assert_eq!(destination.port, target_port);
            assert_eq!(proxy_auth, expected_auth);
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            io::copy_bidirectional(&mut stream, &mut remote)
                .await
                .unwrap();
        });
        port
    }

    async fn read_http_connect_request<S>(stream: &mut S) -> (Destination, Option<String>)
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let request = String::from_utf8_lossy(&request);
        let target = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let proxy_auth = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("Proxy-Authorization")
                .then(|| value.trim().to_owned())
        });
        let target = target.trim_start_matches('[').replace("]:", ":");
        let (host, port) = target.rsplit_once(':').unwrap();
        (
            Destination::tcp(
                DestinationHost::parse(host).unwrap(),
                port.parse::<u16>().unwrap(),
            ),
            proxy_auth,
        )
    }

    async fn start_proxy(
        inbound: InboundConfig,
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_domain_strategy_and_outbounds(
            inbound,
            None,
            rules,
            vec![
                OutboundConfig {
                    tag: "direct".to_owned(),
                    protocol: OutboundProtocol::Freedom,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                },
            ],
        )
        .await
    }

    async fn start_proxy_with_freedom_redirect(
        redirect_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![OutboundConfig {
                tag: "direct".to_owned(),
                protocol: OutboundProtocol::Freedom,
                settings: Some(xrs_config::OutboundSettings {
                    servers: Vec::new(),
                    response: None,
                    redirect: Some(format!("127.0.0.1:{redirect_port}")),
                    extra: std::collections::BTreeMap::new(),
                }),
                stream_settings: None,
                mux: None,
            }],
        )
        .await
    }

    async fn start_proxy_with_blackhole_response(
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            rules,
            vec![
                OutboundConfig {
                    tag: "direct".to_owned(),
                    protocol: OutboundProtocol::Freedom,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    settings: Some(xrs_config::OutboundSettings {
                        servers: Vec::new(),
                        response: Some(xrs_config::BlackholeResponseConfig {
                            kind: "http".to_owned(),
                            extra: std::collections::BTreeMap::new(),
                        }),
                        redirect: None,
                        extra: std::collections::BTreeMap::new(),
                    }),
                    stream_settings: None,
                    mux: None,
                },
            ],
        )
        .await
    }

    async fn start_test_proxy_with_domain_strategy(
        protocol: InboundProtocol,
        domain_strategy: Option<String>,
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_domain_strategy_and_outbounds(
            test_inbound(protocol),
            domain_strategy,
            rules,
            vec![
                OutboundConfig {
                    tag: "direct".to_owned(),
                    protocol: OutboundProtocol::Freedom,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                },
            ],
        )
        .await
    }

    async fn start_proxy_with_outbounds(
        inbound: InboundConfig,
        rules: Vec<xrs_config::RoutingRuleConfig>,
        outbounds: Vec<OutboundConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_domain_strategy_and_outbounds(inbound, None, rules, outbounds).await
    }

    async fn start_proxy_with_domain_strategy_and_outbounds(
        inbound: InboundConfig,
        domain_strategy: Option<String>,
        rules: Vec<xrs_config::RoutingRuleConfig>,
        outbounds: Vec<OutboundConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let (inbound, listener) = bind_inbound(inbound).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds,
            routing: xrs_config::RoutingConfig {
                rules,
                balancers: Vec::new(),
                domain_strategy,
                domain_matcher: None,
            },
            ..RootConfig::default()
        };
        let router = Arc::new(Router::from_config(&config).unwrap());
        let outbounds = Arc::new(
            config
                .outbounds
                .iter()
                .map(|outbound| (outbound.tag.clone(), outbound.clone()))
                .collect::<HashMap<_, _>>(),
        );
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_inbound(
                inbound,
                listener,
                router,
                outbounds,
                counters,
                Arc::new(VmessReplayCache::default()),
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn write_socks_connect<S>(client: &mut S, host: &str, port: u16)
    where
        S: AsyncWrite + Unpin,
    {
        let host = host.as_bytes();
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&port.to_be_bytes());
        client.write_all(&request).await.unwrap();
    }
}
