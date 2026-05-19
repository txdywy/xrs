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
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::{setsockopt, sockopt::TcpFastOpenConnect};
use regex::Regex;
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};
use socket2::{SockRef, TcpKeepalive};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, SocketAddr},
    str,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{Semaphore, mpsc},
    time::timeout,
};
use tracing::{debug, info};
use uuid::Uuid;
use xrs_common::{Destination, DestinationHost, Network, SessionContext};
use xrs_config::{InboundConfig, InboundProtocol, OutboundConfig, OutboundProtocol, RootConfig};
use xrs_observability::{TrafficCounterPolicy, TrafficCounters};
use xrs_router::{Router, RoutingDomainStrategy};

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
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
const VMESS_SECURITY_AES_128_GCM: u8 = 3;
const VMESS_SECURITY_CHACHA20_POLY1305: u8 = 4;
const VMESS_SECURITY_NONE: u8 = 5;
const VMESS_OPTION_CHUNK_STREAM: u8 = 0x01;
const VMESS_OPTION_CHUNK_MASKING: u8 = 0x04;
const VMESS_MAX_CHUNK: usize = 0x3fff;
const VMESS_AUTH_ID_TTL: i64 = 120;
const VMESS_REPLAY_CACHE_MAX: usize = 4096;

type DnsHosts = Arc<RuntimeDns>;

#[derive(Clone, Default)]
struct RuntimeDns {
    hosts: HashMap<String, IpAddr>,
    servers: Vec<RuntimeDnsServer>,
    query_strategy: Option<String>,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
}

#[derive(Clone)]
struct RuntimeDnsServer {
    address: String,
    port: u16,
    transport: RuntimeDnsTransport,
    domains: Vec<String>,
    expect_ips: Vec<RuntimeIpMatcher>,
    client_ip: Option<IpAddr>,
    query_strategy: Option<String>,
    skip_fallback: bool,
}

#[derive(Clone, Copy)]
enum RuntimeDnsTransport {
    Udp,
    Tcp,
}

#[derive(Clone)]
enum RuntimeIpMatcher {
    Exact(IpAddr),
    Network(ipnet::IpNet),
    Private,
    Cn,
}

impl RuntimeIpMatcher {
    fn parse(value: &str) -> Option<Self> {
        if let Some(name) = value.strip_prefix("geoip:") {
            return match name {
                "private" => Some(Self::Private),
                "cn" => Some(Self::Cn),
                _ => None,
            };
        }
        if value.contains('/') {
            return value.parse::<ipnet::IpNet>().ok().map(Self::Network);
        }

        value.parse::<IpAddr>().ok().map(Self::Exact)
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Exact(exact) => *exact == ip,
            Self::Network(network) => network.contains(&ip),
            Self::Private => runtime_is_private_ip(ip),
            Self::Cn => runtime_is_cn_ip(ip),
        }
    }
}

fn runtime_is_cn_ip(ip: IpAddr) -> bool {
    const CN_V4_CIDRS: &[&str] = &["1.0.1.0/24", "1.0.2.0/23"];
    CN_V4_CIDRS.iter().any(|cidr| {
        cidr.parse::<ipnet::IpNet>()
            .is_ok_and(|network| network.contains(&ip))
    })
}

fn runtime_is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || octets[0] == 100 && (64..=127).contains(&octets[1])
                || octets[0] == 192 && octets[1] == 0 && octets[2] == 2
                || octets[0] == 198 && (18..=19).contains(&octets[1])
                || octets[0] == 198 && octets[1] == 51 && octets[2] == 100
                || octets[0] == 203 && octets[1] == 0 && octets[2] == 113
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
        }
    }
}

fn policy_handshake_timeout(policy: Option<&serde_json::Value>) -> Duration {
    policy
        .and_then(|policy| policy.get("levels"))
        .and_then(|levels| levels.get("0"))
        .and_then(|level| level.get("handshake"))
        .and_then(serde_json::Value::as_u64)
        .map_or(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs)
}

fn policy_traffic_counters(policy: Option<&serde_json::Value>) -> TrafficCounterPolicy {
    let Some(system) = policy.and_then(|policy| policy.get("system")) else {
        return TrafficCounterPolicy::enabled();
    };

    let inbound_uplink = system
        .get("statsInboundUplink")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let outbound_uplink = system
        .get("statsOutboundUplink")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let inbound_downlink = system
        .get("statsInboundDownlink")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let outbound_downlink = system
        .get("statsOutboundDownlink")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    TrafficCounterPolicy {
        uplink: inbound_uplink || outbound_uplink,
        downlink: inbound_downlink || outbound_downlink,
    }
}

#[derive(Clone)]
struct RuntimeState {
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    dns_hosts: DnsHosts,
    counters: Arc<TrafficCounters>,
    vmess_replay: Arc<VmessReplayCache>,
    handshake_timeout: Duration,
}

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
    #[error("Trojan UDP relay is not supported yet")]
    UnsupportedTrojanUdpRelay,
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
    #[error("VLESS UDP relay is not supported yet")]
    UnsupportedVlessUdpRelay,
    #[error("VLESS address type {0} is not supported")]
    UnsupportedVlessAddress(u8),
    #[error("VLESS request is malformed")]
    MalformedVlessRequest,
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
    #[error("freedom domainStrategy {0} found no matching target address")]
    NoFreedomAddressForDomainStrategy(String),
    #[error("freedom proxyProtocol requires inbound source address")]
    MissingProxyProtocolSource,
}

const PROXY_V1_PREFIX: &[u8] = b"PROXY ";
const PROXY_V1_MAX_LINE: usize = 108;
const PROXY_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

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
    routing_destination: Option<Destination>,
    remote_prefix: Vec<u8>,
    client_prefix: Vec<u8>,
    shadowsocks: Option<ShadowsocksSession>,
    vmess: Option<VmessSession>,
    socks_udp: Option<SocksUdpAssociate>,
    user: Option<String>,
    protocol: Option<String>,
    attributes: HashMap<String, String>,
}

impl AcceptedInbound {
    fn new(destination: Destination) -> Self {
        Self {
            destination,
            routing_destination: None,
            remote_prefix: Vec::new(),
            client_prefix: Vec::new(),
            shadowsocks: None,
            vmess: None,
            socks_udp: None,
            user: None,
            protocol: None,
            attributes: HashMap::new(),
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
        let counter_policy = policy_traffic_counters(config.policy.as_ref());
        Ok(Self {
            router: Router::from_config(&config)?,
            config,
            counters: Arc::new(TrafficCounters::with_policy(counter_policy)),
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
        let dns_hosts = Arc::new(parse_runtime_dns(self.config.dns.as_ref()));
        let router = Arc::new(self.router);
        let vmess_replay = Arc::new(VmessReplayCache::default());
        let handshake_timeout = policy_handshake_timeout(self.config.policy.as_ref());
        let mut listeners = Vec::with_capacity(self.config.inbounds.len());

        for inbound in self.config.inbounds.clone() {
            if shadowsocks_udp_enabled(&inbound) {
                let socket = bind_udp_inbound(&inbound).await?;
                let inbound = inbound.clone();
                let router = Arc::clone(&router);
                let outbounds = Arc::clone(&outbounds);
                let dns_hosts = Arc::clone(&dns_hosts);
                let counters = Arc::clone(&self.counters);
                tokio::spawn(async move {
                    if let Err(error) = run_shadowsocks_udp_inbound(
                        inbound, socket, router, outbounds, dns_hosts, counters,
                    )
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
            let dns_hosts = Arc::clone(&dns_hosts);
            let counters = Arc::clone(&self.counters);
            let vmess_replay = Arc::clone(&vmess_replay);
            tokio::spawn(async move {
                if let Err(error) = run_inbound(
                    inbound,
                    listener,
                    RuntimeState {
                        router,
                        outbounds,
                        dns_hosts,
                        counters,
                        vmess_replay,
                        handshake_timeout,
                    },
                )
                .await
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

async fn accept_inbound_client(
    listener: &TcpListener,
    inbound: &InboundConfig,
) -> Result<AcceptedClient, CoreError> {
    let (stream, peer) = listener.accept().await?;
    apply_tcp_socket_options(&stream, inbound.stream_settings.as_ref())?;
    Ok(AcceptedClient {
        stream,
        source_ip: peer.ip(),
        source_port: peer.port(),
    })
}

fn inbound_accepts_proxy_protocol(inbound: &InboundConfig) -> bool {
    inbound
        .stream_settings
        .as_ref()
        .and_then(|settings| {
            settings
                .tcp_settings
                .as_ref()
                .or(settings.raw_settings.as_ref())
        })
        .is_some_and(|settings| settings.accept_proxy_protocol)
}

async fn read_proxy_source(stream: &mut TcpStream) -> Result<Option<SocketAddr>, CoreError> {
    let mut prefix = [0_u8; 12];
    stream.read_exact(&mut prefix).await?;
    if &prefix == PROXY_V2_SIGNATURE {
        return read_proxy_v2_source(stream).await;
    }

    let mut line = prefix.to_vec();
    loop {
        if line.len() >= PROXY_V1_MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY header too long").into());
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
    }
    parse_proxy_v1_source(&line)
}

async fn read_proxy_v2_source(stream: &mut TcpStream) -> Result<Option<SocketAddr>, CoreError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    parse_proxy_v2_source(header[0], header[1], &payload)
}

fn parse_proxy_v2_source(
    version_command: u8,
    family_protocol: u8,
    payload: &[u8],
) -> Result<Option<SocketAddr>, CoreError> {
    match version_command {
        0x20 => return Ok(None),
        0x21 => {}
        _ => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY v2 command").into(),
            );
        }
    }
    match family_protocol {
        0x00 => Ok(None),
        0x11 => {
            if payload.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PROXY v2 TCP4 payload",
                )
                .into());
            }
            let source_ip = IpAddr::from([payload[0], payload[1], payload[2], payload[3]]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        0x21 => {
            if payload.len() < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PROXY v2 TCP6 payload",
                )
                .into());
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[..16]);
            let source_ip = IpAddr::from(octets);
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY v2 family").into()),
    }
}

fn parse_proxy_v1_source(line: &[u8]) -> Result<Option<SocketAddr>, CoreError> {
    if !line.starts_with(PROXY_V1_PREFIX) || !line.ends_with(b"\r\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY header").into());
    }
    let line = str::from_utf8(&line[..line.len() - 2])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some("PROXY") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY header").into());
    }
    let family = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PROXY family"))?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    if !matches!(family, "TCP4" | "TCP6") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY family").into());
    }
    let source_ip = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PROXY source ip"))?
        .parse::<IpAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let destination_ip = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PROXY destination ip"))?
        .parse::<IpAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let source_port = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PROXY source port"))?
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let _destination_port = parts
        .next()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing PROXY destination port")
        })?
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if parts.next().is_some()
        || source_ip.is_ipv4() != (family == "TCP4")
        || destination_ip.is_ipv4() != (family == "TCP4")
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY source").into());
    }
    Ok(Some(SocketAddr::new(source_ip, source_port)))
}

async fn run_inbound(
    inbound: InboundConfig,
    listener: TcpListener,
    state: RuntimeState,
) -> Result<(), CoreError> {
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_INBOUND));
    let tls_acceptor = inbound_tls_acceptor(&inbound)?;

    loop {
        let accepted_client = accept_inbound_client(&listener, &inbound).await?;
        debug!(peer = %SocketAddr::new(accepted_client.source_ip, accepted_client.source_port), tag = inbound.tag, "accepted connection");
        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let peer = SocketAddr::new(accepted_client.source_ip, accepted_client.source_port);
                let mut stream = accepted_client.stream;
                stream.shutdown().await?;
                tracing::debug!(%peer, tag = inbound.tag, "connection limit reached");
                continue;
            }
        };
        let inbound = inbound.clone();
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_client(accepted_client, tls_acceptor, inbound, state).await {
                tracing::debug!(%error, "connection finished with error");
            }
        });
    }
}

async fn pick_tcp_outbound<'a>(
    router: &'a Router,
    session: &SessionContext,
    destination: &Destination,
    dns_hosts: &DnsHosts,
) -> Result<&'a str, CoreError> {
    if !matches!(session.destination.host, DestinationHost::Domain(_)) {
        return Ok(router.pick_outbound(session));
    }

    match router.domain_strategy() {
        RoutingDomainStrategy::AsIs => Ok(router.pick_outbound(session)),
        RoutingDomainStrategy::IpIfNonMatch => {
            if let Some(outbound) = router.pick_rule_outbound(session) {
                return Ok(outbound);
            }
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(router
                .pick_rule_outbound_for_any(&resolved_sessions)
                .unwrap_or(router.default_outbound()))
        }
        RoutingDomainStrategy::IpOnDemand => {
            let mut sessions = vec![session.clone()];
            sessions.extend(
                resolve_destination_sessions(
                    session,
                    destination,
                    dns_hosts,
                    routing_dns_query_strategy(router.domain_strategy()),
                )
                .await?,
            );
            Ok(router
                .pick_rule_outbound_for_any(&sessions)
                .unwrap_or(router.default_outbound()))
        }
        RoutingDomainStrategy::UseIpv4 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V4,
                None,
            ))
        }
        RoutingDomainStrategy::UseIpv6 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V6,
                None,
            ))
        }
        RoutingDomainStrategy::UseIpv4v6 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V4,
                Some(IpFamily::V6),
            ))
        }
        RoutingDomainStrategy::UseIpv6v4 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V6,
                Some(IpFamily::V4),
            ))
        }
    }
}

async fn pick_udp_outbound<'a>(
    router: &'a Router,
    session: &SessionContext,
    destination: &Destination,
    dns_hosts: &DnsHosts,
) -> Result<&'a str, CoreError> {
    if !matches!(session.destination.host, DestinationHost::Domain(_)) {
        return Ok(router.pick_outbound(session));
    }

    match router.domain_strategy() {
        RoutingDomainStrategy::AsIs => Ok(router.pick_outbound(session)),
        RoutingDomainStrategy::IpIfNonMatch => {
            if let Some(outbound) = router.pick_rule_outbound(session) {
                return Ok(outbound);
            }
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(router
                .pick_rule_outbound_for_any(&resolved_sessions)
                .unwrap_or(router.default_outbound()))
        }
        RoutingDomainStrategy::IpOnDemand => {
            let mut sessions = vec![session.clone()];
            sessions.extend(
                resolve_destination_sessions(
                    session,
                    destination,
                    dns_hosts,
                    routing_dns_query_strategy(router.domain_strategy()),
                )
                .await?,
            );
            Ok(router
                .pick_rule_outbound_for_any(&sessions)
                .unwrap_or(router.default_outbound()))
        }
        RoutingDomainStrategy::UseIpv4 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V4,
                None,
            ))
        }
        RoutingDomainStrategy::UseIpv6 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V6,
                None,
            ))
        }
        RoutingDomainStrategy::UseIpv4v6 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V4,
                Some(IpFamily::V6),
            ))
        }
        RoutingDomainStrategy::UseIpv6v4 => {
            let resolved_sessions = resolve_destination_sessions(
                session,
                destination,
                dns_hosts,
                routing_dns_query_strategy(router.domain_strategy()),
            )
            .await?;
            Ok(pick_family_rule_outbound(
                router,
                resolved_sessions,
                IpFamily::V6,
                Some(IpFamily::V4),
            ))
        }
    }
}

fn routing_dns_query_strategy(strategy: RoutingDomainStrategy) -> Option<&'static str> {
    match strategy {
        RoutingDomainStrategy::UseIpv4 => Some("UseIPv4"),
        RoutingDomainStrategy::UseIpv6 => Some("UseIPv6"),
        RoutingDomainStrategy::UseIpv4v6 => Some("UseIPv4v6"),
        RoutingDomainStrategy::UseIpv6v4 => Some("UseIPv6v4"),
        RoutingDomainStrategy::AsIs
        | RoutingDomainStrategy::IpIfNonMatch
        | RoutingDomainStrategy::IpOnDemand => None,
    }
}

fn pick_family_rule_outbound(
    router: &Router,
    sessions: Vec<SessionContext>,
    preferred_family: IpFamily,
    fallback_family: Option<IpFamily>,
) -> &str {
    let preferred_sessions = sessions
        .iter()
        .filter(|session| session_ip_matches_family(session, preferred_family))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(outbound) = router.pick_ip_rule_outbound_for_any(&preferred_sessions) {
        return outbound;
    }

    if let Some(fallback_family) = fallback_family {
        let fallback_sessions = sessions
            .iter()
            .filter(|session| session_ip_matches_family(session, fallback_family))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(outbound) = router.pick_ip_rule_outbound_for_any(&fallback_sessions) {
            return outbound;
        }
    }

    router.default_outbound()
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

fn session_ip_matches_family(session: &SessionContext, family: IpFamily) -> bool {
    match (&session.destination.host, family) {
        (DestinationHost::Ip(ip), IpFamily::V4) => ip.is_ipv4(),
        (DestinationHost::Ip(ip), IpFamily::V6) => ip.is_ipv6(),
        _ => false,
    }
}

async fn resolve_destination_sessions(
    session: &SessionContext,
    destination: &Destination,
    dns_hosts: &DnsHosts,
    query_strategy: Option<&str>,
) -> Result<Vec<SessionContext>, CoreError> {
    if let DestinationHost::Domain(domain) = &destination.host {
        if let Some(address) = dns_hosts_lookup(&dns_hosts.hosts, domain) {
            return Ok(vec![resolved_session(session, destination, address)]);
        }
        match resolve_domain_with_dns_servers(dns_hosts, domain, query_strategy).await? {
            DnsServerResolution::Resolved(address) => {
                return Ok(vec![resolved_session(session, destination, address)]);
            }
            DnsServerResolution::SuppressedFallback => return Ok(vec![session.clone()]),
            DnsServerResolution::Miss => {}
        }
    }

    Ok(
        lookup_host((destination.host.to_string(), destination.port))
            .await?
            .map(|address| resolved_session(session, destination, address.ip()))
            .collect(),
    )
}

fn resolved_session(
    session: &SessionContext,
    destination: &Destination,
    address: IpAddr,
) -> SessionContext {
    SessionContext {
        inbound_tag: session.inbound_tag.clone(),
        destination: Destination {
            host: DestinationHost::Ip(address),
            port: destination.port,
            network: destination.network,
        },
        source_ip: session.source_ip,
        source_port: session.source_port,
        user: session.user.clone(),
        protocol: session.protocol.clone(),
        attributes: session.attributes.clone(),
    }
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
    let protocols = inbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.tls_settings.as_ref())
        .map(|settings| settings.alpn.iter().map(String::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let certificate = std::fs::read(certificate_file)?;
    let key = std::fs::read(key_file)?;
    let identity = Identity::from_pkcs8(&certificate, &key)?;
    let mut builder = native_tls::TlsAcceptor::builder(identity);
    if !protocols.is_empty() {
        builder.accept_alpn(&protocols);
    }
    Ok(Some(tokio_native_tls::TlsAcceptor::from(builder.build()?)))
}

async fn handle_client(
    accepted_client: AcceptedClient,
    tls_acceptor: Option<tokio_native_tls::TlsAcceptor>,
    inbound: InboundConfig,
    state: RuntimeState,
) -> Result<(), CoreError> {
    let RuntimeState {
        router,
        outbounds,
        dns_hosts,
        counters,
        vmess_replay,
        handshake_timeout,
    } = state;
    let mut accepted_client = accepted_client;
    if inbound_accepts_proxy_protocol(&inbound)
        && let Some(source) = timeout(
            handshake_timeout,
            read_proxy_source(&mut accepted_client.stream),
        )
        .await
        .map_err(|_| CoreError::Timeout)??
    {
        accepted_client.source_ip = source.ip();
        accepted_client.source_port = source.port();
    }
    let source_ip = accepted_client.source_ip;
    let source_port = accepted_client.source_port;
    let mut client = match tls_acceptor {
        Some(acceptor) => InboundStream::Tls(
            timeout(handshake_timeout, acceptor.accept(accepted_client.stream))
                .await
                .map_err(|_| CoreError::Timeout)??,
        ),
        None => InboundStream::Tcp(accepted_client.stream),
    };
    let mut accepted = timeout(handshake_timeout, async {
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
    if accepted.remote_prefix.is_empty() {
        let metadata_only = inbound_sniffing_metadata_only(&inbound);
        let route_only = inbound_sniffing_route_only(&inbound) && !metadata_only;
        let rewrite_destination = !route_only && !metadata_only;
        let domains_excluded = inbound_sniffing_domains_excluded(&inbound);
        let mut sniffed_tls = false;
        if inbound_sniffs_tls(&inbound) {
            sniffed_tls = timeout(
                handshake_timeout,
                sniff_tls_destination(
                    &mut client,
                    &mut accepted,
                    route_only,
                    rewrite_destination,
                    &domains_excluded,
                ),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
        }
        if !sniffed_tls && inbound_sniffs_http(&inbound) {
            timeout(
                handshake_timeout,
                sniff_http_destination(
                    &mut client,
                    &mut accepted,
                    route_only,
                    rewrite_destination,
                    &domains_excluded,
                ),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
        }
    }
    let sniff_quic = inbound_sniffs_quic(&inbound);
    if let Some(associate) = accepted.socks_udp {
        let allowed_peer_ip = client.peer_addr()?.ip();
        return handle_socks_udp_associate(
            client,
            associate,
            allowed_peer_ip,
            UdpRelayContext {
                source_ip,
                source_port,
                inbound_tag: inbound.tag,
                router,
                outbounds,
                dns_hosts,
                counters,
                sniff_quic,
            },
        )
        .await;
    }
    let destination = accepted.destination.clone();
    if inbound.protocol == InboundProtocol::Trojan && destination.network == Network::Udp {
        return handle_trojan_udp_relay(
            client,
            accepted,
            UdpRelayContext {
                source_ip,
                source_port,
                inbound_tag: inbound.tag,
                router,
                outbounds,
                dns_hosts,
                counters,
                sniff_quic,
            },
        )
        .await;
    }
    if inbound.protocol == InboundProtocol::Vless && destination.network == Network::Udp {
        return handle_vless_udp_relay(
            client,
            accepted,
            UdpRelayContext {
                source_ip,
                source_port,
                inbound_tag: inbound.tag,
                router,
                outbounds,
                dns_hosts,
                counters,
                sniff_quic,
            },
        )
        .await;
    }
    if inbound.protocol == InboundProtocol::Vmess && destination.network == Network::Udp {
        return handle_vmess_udp_relay(
            client,
            accepted,
            UdpRelayContext {
                source_ip,
                source_port,
                inbound_tag: inbound.tag,
                router,
                outbounds,
                dns_hosts,
                counters,
                sniff_quic,
            },
        )
        .await;
    }
    let route_destination = accepted
        .routing_destination
        .clone()
        .unwrap_or_else(|| destination.clone());
    let mut session = SessionContext::new(inbound.tag, route_destination.clone())
        .with_source_ip(source_ip)
        .with_source_port(source_port);
    if let Some(user) = accepted.user.as_ref() {
        session = session.with_user(user.clone());
    }
    if let Some(protocol) = accepted.protocol.as_ref() {
        session = session.with_protocol(protocol.clone());
    }
    for (name, value) in &accepted.attributes {
        session = session.with_attribute(name.clone(), value.clone());
    }
    let outbound_tag = pick_tcp_outbound(&router, &session, &route_destination, &dns_hosts).await?;
    let outbound = outbounds
        .get(outbound_tag)
        .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;

    match outbound.protocol {
        OutboundProtocol::Freedom => {
            let uses_tls = outbound
                .stream_settings
                .as_ref()
                .and_then(|settings| settings.security.as_deref())
                == Some("tls");
            if let Some(session) = accepted.shadowsocks {
                if uses_tls {
                    return Err(CoreError::UnsupportedTlsEncryptedRelay);
                }
                let source = Some(SocketAddr::new(source_ip, source_port));
                let mut remote = connect_freedom_for_outbound(
                    outbound,
                    &destination,
                    source,
                    &outbounds,
                    &dns_hosts,
                )
                .await?;
                write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
                write_client_prefix(&mut client, &accepted.client_prefix).await?;
                relay_shadowsocks_to_plain(client, session, remote, counters).await?;
            } else if let Some(session) = accepted.vmess {
                if uses_tls {
                    return Err(CoreError::UnsupportedTlsEncryptedRelay);
                }
                let source = Some(SocketAddr::new(source_ip, source_port));
                let mut remote = connect_freedom_for_outbound(
                    outbound,
                    &destination,
                    source,
                    &outbounds,
                    &dns_hosts,
                )
                .await?;
                write_remote_prefix(&mut remote, &accepted.remote_prefix).await?;
                write_client_prefix(&mut client, &accepted.client_prefix).await?;
                relay_vmess_to_plain(client, session, remote, counters).await?;
            } else {
                let source = Some(SocketAddr::new(source_ip, source_port));
                let mut remote = connect_freedom_for_outbound(
                    outbound,
                    &destination,
                    source,
                    &outbounds,
                    &dns_hosts,
                )
                .await?;
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
                DEFAULT_HANDSHAKE_TIMEOUT,
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
                DEFAULT_HANDSHAKE_TIMEOUT,
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
        OutboundProtocol::Trojan => {
            let mut remote = timeout(
                DEFAULT_HANDSHAKE_TIMEOUT,
                connect_trojan_upstream(outbound, &destination),
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
        OutboundProtocol::Vless => {
            let mut remote = timeout(
                DEFAULT_HANDSHAKE_TIMEOUT,
                connect_vless_upstream(outbound, &destination),
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
    }

    Ok(())
}

async fn resolve_domain_with_dns_servers(
    dns: &RuntimeDns,
    domain: &str,
    query_strategy: Option<&str>,
) -> Result<DnsServerResolution, CoreError> {
    let has_filtered_match = dns
        .servers
        .iter()
        .any(|server| !server.domains.is_empty() && dns_server_matches_domain(server, domain));
    let suppress_generic_servers =
        dns.disable_fallback || dns.disable_fallback_if_match && has_filtered_match;

    for server in dns
        .servers
        .iter()
        .filter(|server| dns_server_matches_domain(server, domain))
        .filter(|server| !suppress_generic_servers || !server.domains.is_empty())
        .filter(|server| !server.skip_fallback || !server.domains.is_empty())
    {
        let query_strategy = server
            .query_strategy
            .as_deref()
            .or(query_strategy)
            .or(dns.query_strategy.as_deref());
        if let Some(address) = query_dns_server_for_record(server, domain, query_strategy).await?
            && dns_server_accepts_ip(server, address)
        {
            return Ok(DnsServerResolution::Resolved(address));
        }
    }
    if suppress_generic_servers && (dns.disable_fallback || has_filtered_match) {
        Ok(DnsServerResolution::SuppressedFallback)
    } else {
        Ok(DnsServerResolution::Miss)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsServerResolution {
    Resolved(IpAddr),
    SuppressedFallback,
    Miss,
}

fn dns_server_matches_domain(server: &RuntimeDnsServer, domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    server.domains.is_empty()
        || server
            .domains
            .iter()
            .any(|matcher| sniffed_domain_matches_exclusion(&domain, matcher))
}

fn dns_server_accepts_ip(server: &RuntimeDnsServer, address: IpAddr) -> bool {
    server.expect_ips.is_empty()
        || server
            .expect_ips
            .iter()
            .any(|matcher| matcher.matches(address))
}

async fn query_dns_server_for_record(
    server: &RuntimeDnsServer,
    domain: &str,
    query_strategy: Option<&str>,
) -> Result<Option<IpAddr>, CoreError> {
    for &record_type in dns_query_record_types(query_strategy) {
        let query = build_dns_query(domain, record_type, server.client_ip)?;
        let address = match server.transport {
            RuntimeDnsTransport::Udp => {
                query_udp_dns_server_for_record(server, &query, record_type).await?
            }
            RuntimeDnsTransport::Tcp => {
                query_tcp_dns_server_for_record(server, &query, record_type).await?
            }
        };
        if address.is_some() {
            return Ok(address);
        }
    }
    Ok(None)
}

fn dns_query_record_types(query_strategy: Option<&str>) -> &'static [u16] {
    match query_strategy {
        Some("UseIPv6") => &[28],
        Some("UseIP") | Some("UseIPv4v6") => &[1, 28],
        Some("UseIPv6v4") => &[28, 1],
        _ => &[1],
    }
}

async fn query_udp_dns_server_for_record(
    server: &RuntimeDnsServer,
    query: &[u8],
    record_type: u16,
) -> Result<Option<IpAddr>, CoreError> {
    let socket = connect_udp_to_host(&server.address, server.port).await?;
    timeout(DNS_TIMEOUT, socket.send(query))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_SIZE];
    let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(parse_dns_response(&response[..length], query, record_type))
}

async fn query_tcp_dns_server_for_record(
    server: &RuntimeDnsServer,
    query: &[u8],
    record_type: u16,
) -> Result<Option<IpAddr>, CoreError> {
    let mut stream = timeout(
        DNS_TIMEOUT,
        TcpStream::connect((server.address.as_str(), server.port)),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    let query_len = u16::try_from(query.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    timeout(DNS_TIMEOUT, stream.write_all(&query_len.to_be_bytes()))
        .await
        .map_err(|_| CoreError::Timeout)??;
    timeout(DNS_TIMEOUT, stream.write_all(query))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let mut response_len = [0_u8; 2];
    timeout(DNS_TIMEOUT, stream.read_exact(&mut response_len))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len == 0 {
        return Err(CoreError::InvalidDnsMessageLength);
    }
    if response_len > MAX_DNS_MESSAGE_SIZE {
        return Err(CoreError::DnsMessageTooLarge);
    }
    let mut response = vec![0_u8; response_len];
    timeout(DNS_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(parse_dns_response(&response, query, record_type))
}

fn build_dns_query(
    domain: &str,
    record_type: u16,
    client_ip: Option<IpAddr>,
) -> Result<Vec<u8>, CoreError> {
    let domain = normalize_dns_host_key(domain)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS query domain"))?;
    let additional_records = u8::from(client_ip.is_some());
    let mut query = vec![
        0x12,
        0x34,
        0x01,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        additional_records,
    ];
    for label in domain.split('.') {
        let label = label.as_bytes();
        let label_len = u8::try_from(label.len())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if label_len == 0 || label_len > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS label").into());
        }
        query.push(label_len);
        query.extend_from_slice(label);
    }
    query.push(0x00);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);
    if let Some(client_ip) = client_ip {
        append_dns_client_subnet_option(&mut query, client_ip);
    }
    Ok(query)
}

fn append_dns_client_subnet_option(query: &mut Vec<u8>, client_ip: IpAddr) {
    let (family, source_prefix, address) = match client_ip {
        IpAddr::V4(ip) => (1_u16, 32_u8, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2_u16, 128_u8, ip.octets().to_vec()),
    };
    let option_len = 4 + address.len();
    query.extend_from_slice(&[0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
    query.extend_from_slice(&(4 + option_len as u16).to_be_bytes());
    query.extend_from_slice(&8_u16.to_be_bytes());
    query.extend_from_slice(&(option_len as u16).to_be_bytes());
    query.extend_from_slice(&family.to_be_bytes());
    query.push(source_prefix);
    query.push(0);
    query.extend_from_slice(&address);
}

fn parse_dns_response(response: &[u8], query: &[u8], expected_record_type: u16) -> Option<IpAddr> {
    if response.len() < 12
        || response[..2] != [0x12, 0x34]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != 0
        || response[2] & 0x02 != 0
        || response[3] & 0x0f != 0
    {
        return None;
    }
    let questions = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;
    if questions != 1 {
        return None;
    }
    let query_question_end = skip_dns_name(query, 12)?;
    if query_question_end.checked_add(4)? > query.len() {
        return None;
    }
    let query_question = &query[12..query_question_end + 4];
    let question_name = &query[12..query_question_end];

    let mut offset = 12;
    let question_name_offset = offset;
    let question_name_end = skip_dns_name(response, offset)?;
    if question_name_end.checked_add(4)? > response.len() {
        return None;
    }
    if response.get(question_name_offset..question_name_end + 4)? != query_question {
        return None;
    }
    let mut accepted_answer_names = vec![question_name.to_vec()];
    offset = question_name_end + 4;
    for _ in 0..answers {
        let answer_name_offset = offset;
        offset = skip_dns_name(response, offset)?;
        if offset.checked_add(10)? > response.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let record_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let data_len = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if offset.checked_add(data_len)? > response.len() {
            return None;
        }
        if record_type == 5 && record_class == 1 {
            let cname_end = skip_dns_name(response, offset)?;
            if cname_end == offset + data_len
                && dns_name_at_matches_any(response, answer_name_offset, &accepted_answer_names)?
            {
                accepted_answer_names.push(expand_dns_name(response, offset)?);
            }
        }
        if record_type == expected_record_type && record_class == 1 {
            if !dns_name_at_matches_any(response, answer_name_offset, &accepted_answer_names)? {
                return None;
            }
            return match (record_type, data_len) {
                (1, 4) => Some(IpAddr::from([
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                ])),
                (28, 16) => Some(IpAddr::from([
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                    response[offset + 4],
                    response[offset + 5],
                    response[offset + 6],
                    response[offset + 7],
                    response[offset + 8],
                    response[offset + 9],
                    response[offset + 10],
                    response[offset + 11],
                    response[offset + 12],
                    response[offset + 13],
                    response[offset + 14],
                    response[offset + 15],
                ])),
                _ => None,
            };
        }
        offset += data_len;
    }
    None
}

fn dns_name_at_matches_any(message: &[u8], offset: usize, names: &[Vec<u8>]) -> Option<bool> {
    let name = expand_dns_name(message, offset)?;
    Some(names.iter().any(|candidate| candidate == &name))
}

fn expand_dns_name(message: &[u8], mut offset: usize) -> Option<Vec<u8>> {
    let mut name = Vec::new();
    let mut jumps = 0;
    loop {
        let length = *message.get(offset)?;
        offset += 1;
        if length == 0 {
            name.push(0);
            return Some(name);
        }
        if length & 0xc0 == 0xc0 {
            let second = *message.get(offset)?;
            offset = (((length & 0x3f) as usize) << 8) | second as usize;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        name.push(length);
        name.extend_from_slice(message.get(offset..end)?);
        offset = end;
    }
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)?;
        offset += 1;
        if length == 0 {
            return Some(offset);
        }
        if length & 0xc0 == 0xc0 {
            message.get(offset)?;
            return Some(offset + 1);
        }
        if length & 0xc0 != 0 {
            return None;
        }
        offset = offset.checked_add(length as usize)?;
        if offset > message.len() {
            return None;
        }
    }
}

fn dns_hosts_lookup(dns_hosts: &HashMap<String, IpAddr>, domain: &str) -> Option<IpAddr> {
    let domain = normalize_dns_host_key(domain)?;
    dns_hosts.get(&domain).copied().or_else(|| {
        dns_hosts.iter().find_map(|(host, address)| {
            let suffix = host.strip_prefix("domain:");
            let keyword = host.strip_prefix("keyword:");
            let pattern = host.strip_prefix("regexp:");
            (suffix
                .is_some_and(|suffix| domain == suffix || domain.ends_with(&format!(".{suffix}")))
                || keyword.is_some_and(|keyword| domain.contains(keyword))
                || pattern.is_some_and(|pattern| {
                    Regex::new(pattern).is_ok_and(|regex| regex.is_match(&domain))
                }))
            .then_some(*address)
        })
    })
}

fn parse_runtime_dns(dns: Option<&serde_json::Value>) -> RuntimeDns {
    RuntimeDns {
        hosts: parse_dns_hosts(dns),
        servers: parse_dns_servers(dns),
        query_strategy: dns.and_then(dns_query_strategy).map(str::to_owned),
        disable_fallback: dns
            .and_then(|dns| dns.get("disableFallback"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        disable_fallback_if_match: dns
            .and_then(|dns| dns.get("disableFallbackIfMatch"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    }
}

fn dns_client_ip(dns: &serde_json::Value) -> Option<IpAddr> {
    dns.get("clientIp")
        .or_else(|| dns.get("clientIP"))?
        .as_str()?
        .parse()
        .ok()
}

fn parse_runtime_dns_server_address(address: &str) -> Option<(String, u16, RuntimeDnsTransport)> {
    if address.trim().is_empty() {
        return None;
    }

    if let Some(address) = address.strip_prefix("tcp://") {
        let (address, port) = parse_dns_uri_authority(address)?;
        return Some((address, port, RuntimeDnsTransport::Tcp));
    }
    if let Some(address) = address.strip_prefix("udp://") {
        let (address, port) = parse_dns_uri_authority(address)?;
        return Some((address, port, RuntimeDnsTransport::Udp));
    }
    if address.contains("://") {
        return None;
    }
    Some((address.to_owned(), 53, RuntimeDnsTransport::Udp))
}

fn parse_dns_uri_authority(address: &str) -> Option<(String, u16)> {
    if let Some(address) = address.strip_prefix('[') {
        let (address, rest) = address.split_once(']')?;
        let port = rest
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .ok()?
            .unwrap_or(53);
        return (!address.is_empty() && port != 0).then(|| (address.to_owned(), port));
    }

    if address.matches(':').count() == 1 {
        let (address, port) = address.rsplit_once(':')?;
        let port = port.parse().ok()?;
        return (!address.is_empty() && port != 0).then(|| (address.to_owned(), port));
    }

    (!address.is_empty()).then(|| (address.to_owned(), 53))
}

fn parse_dns_servers(dns: Option<&serde_json::Value>) -> Vec<RuntimeDnsServer> {
    let top_level_client_ip = dns.and_then(dns_client_ip);
    dns.and_then(|dns| dns.get("servers"))
        .and_then(serde_json::Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| {
                    if let Some(address) = server.as_str() {
                        let (address, port, transport) = parse_runtime_dns_server_address(address)?;
                        return Some(RuntimeDnsServer {
                            address,
                            port,
                            transport,
                            domains: Vec::new(),
                            expect_ips: Vec::new(),
                            client_ip: top_level_client_ip,
                            query_strategy: None,
                            skip_fallback: false,
                        });
                    }
                    let server = server.as_object()?;
                    let (address, default_port, transport) =
                        parse_runtime_dns_server_address(server.get("address")?.as_str()?)?;
                    let port = server
                        .get("port")
                        .and_then(serde_json::Value::as_u64)
                        .map(u16::try_from)
                        .transpose()
                        .ok()?
                        .unwrap_or(default_port);
                    let domains = server
                        .get("domains")
                        .and_then(serde_json::Value::as_array)
                        .map(|domains| {
                            domains
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    let expect_ips = server
                        .get("expectIPs")
                        .and_then(serde_json::Value::as_array)
                        .map(|expect_ips| {
                            expect_ips
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .filter_map(RuntimeIpMatcher::parse)
                                .collect()
                        })
                        .unwrap_or_default();
                    let client_ip = server
                        .get("clientIp")
                        .or_else(|| server.get("clientIP"))
                        .and_then(serde_json::Value::as_str)
                        .map(|client_ip| client_ip.parse().ok())
                        .unwrap_or(top_level_client_ip);
                    let query_strategy = server
                        .get("queryStrategy")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let skip_fallback = server
                        .get("skipFallback")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    Some(RuntimeDnsServer {
                        address,
                        port,
                        transport,
                        domains,
                        expect_ips,
                        client_ip,
                        query_strategy,
                        skip_fallback,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_dns_hosts(dns: Option<&serde_json::Value>) -> HashMap<String, IpAddr> {
    let query_strategy = dns.and_then(dns_query_strategy);
    dns.and_then(|dns| dns.get("hosts"))
        .and_then(|hosts| hosts.as_object())
        .map(|hosts| {
            let hosts = hosts
                .iter()
                .filter_map(|(host, address)| {
                    let matches_subdomains = dns_host_matches_subdomains(host);
                    normalize_dns_host_key(host).map(|host| (host, matches_subdomains, address))
                })
                .collect::<Vec<_>>();

            let mut resolved = HashMap::new();
            for (host, matches_subdomains, address) in &hosts {
                if let Some(address) =
                    parse_dns_host_address(address, &hosts, &mut Vec::new(), query_strategy)
                {
                    resolved.insert(host.clone(), address);
                    if *matches_subdomains {
                        resolved.insert(format!("domain:{host}"), address);
                    }
                }
            }
            resolved
        })
        .unwrap_or_default()
}

fn parse_dns_host_address(
    value: &serde_json::Value,
    hosts: &[(String, bool, &serde_json::Value)],
    visited: &mut Vec<String>,
    query_strategy: Option<&str>,
) -> Option<IpAddr> {
    if let Some(address) = value.as_str() {
        return parse_dns_host_string(address, hosts, visited, query_strategy);
    }

    let addresses = value
        .as_array()?
        .iter()
        .filter_map(|address| parse_dns_host_address(address, hosts, visited, query_strategy));
    pick_dns_host_address(query_strategy, addresses)
}

fn parse_dns_host_string(
    value: &str,
    hosts: &[(String, bool, &serde_json::Value)],
    visited: &mut Vec<String>,
    query_strategy: Option<&str>,
) -> Option<IpAddr> {
    if let Ok(address) = value.parse() {
        return Some(address);
    }

    let alias = normalize_dns_host_key(value)?;
    if visited.contains(&alias) {
        return None;
    }
    let (_, _, target) = hosts.iter().find(|(host, _, _)| host == &alias)?;
    visited.push(alias);
    parse_dns_host_address(target, hosts, visited, query_strategy)
}

fn dns_query_strategy(dns: &serde_json::Value) -> Option<&str> {
    dns.get("queryStrategy")
        .and_then(serde_json::Value::as_str)
        .filter(|strategy| !strategy.is_empty())
}

fn pick_dns_host_address(
    query_strategy: Option<&str>,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Option<IpAddr> {
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    match query_strategy {
        Some("UseIPv4") => addresses.into_iter().find(IpAddr::is_ipv4),
        Some("UseIPv6") => addresses.into_iter().find(IpAddr::is_ipv6),
        Some("UseIPv4v6") => addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.iter().find(|address| address.is_ipv6()))
            .copied(),
        Some("UseIPv6v4") => addresses
            .iter()
            .find(|address| address.is_ipv6())
            .or_else(|| addresses.iter().find(|address| address.is_ipv4()))
            .copied(),
        _ => addresses.first().copied(),
    }
}

fn dns_host_matches_subdomains(host: &str) -> bool {
    host.trim().starts_with("domain:")
}

fn normalize_dns_host_key(host: &str) -> Option<String> {
    let host = host.trim();
    let host = host
        .strip_prefix("domain:")
        .or_else(|| host.strip_prefix("full:"))
        .unwrap_or(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

async fn freedom_destination_with_dns_hosts(
    outbound: &OutboundConfig,
    destination: &Destination,
    dns_hosts: &DnsHosts,
) -> Result<Destination, CoreError> {
    let mut destination = freedom_redirect_destination(outbound, destination)?;
    let mut disable_local_fallback = false;
    if freedom_uses_dns_hosts(outbound)
        && let DestinationHost::Domain(domain) = &destination.host
    {
        if let Some(address) = dns_hosts_lookup(&dns_hosts.hosts, domain) {
            destination.host = DestinationHost::Ip(address);
        } else {
            match resolve_domain_with_dns_servers(dns_hosts, domain, None).await? {
                DnsServerResolution::Resolved(address) => {
                    destination.host = DestinationHost::Ip(address);
                }
                DnsServerResolution::SuppressedFallback => {
                    disable_local_fallback = true;
                }
                DnsServerResolution::Miss => {}
            }
        }
    }
    if disable_local_fallback {
        Ok(destination)
    } else {
        freedom_destination(outbound, &destination).await
    }
}

async fn freedom_destination(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<Destination, CoreError> {
    let mut destination = freedom_redirect_destination(outbound, destination)?;

    if matches!(destination.host, DestinationHost::Domain(_)) {
        let strategy = freedom_domain_strategy(outbound);
        if matches!(
            strategy,
            Some("UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4" | "IPIfNonMatch")
        ) {
            let addresses = lookup_host((destination.host.to_string(), destination.port)).await?;
            if let Some(address) = pick_freedom_address(strategy, addresses)? {
                destination.host = DestinationHost::Ip(address.ip());
            }
        }
    }

    Ok(destination)
}

fn freedom_redirect_destination(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<Destination, CoreError> {
    let Some(redirect) = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.redirect.as_deref())
    else {
        return Ok(destination.clone());
    };
    let (host, port) = parse_redirect_target(redirect)?;
    Ok(Destination {
        host,
        port,
        network: destination.network,
    })
}

fn freedom_uses_dns_hosts(outbound: &OutboundConfig) -> bool {
    !matches!(freedom_domain_strategy(outbound), Some("AsIs"))
}

fn freedom_domain_strategy(outbound: &OutboundConfig) -> Option<&str> {
    outbound
        .settings
        .as_ref()
        .and_then(|settings| {
            settings
                .target_strategy
                .as_deref()
                .or(settings.domain_strategy.as_deref())
        })
        .or_else(|| {
            outbound
                .stream_settings
                .as_ref()
                .and_then(|settings| settings.sockopt.as_ref())
                .and_then(|sockopt| sockopt.domain_strategy.as_deref())
        })
}

fn pick_freedom_address(
    strategy: Option<&str>,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Option<SocketAddr>, CoreError> {
    let addresses: Vec<_> = addresses.into_iter().collect();
    let address = match strategy {
        Some("UseIPv4") => addresses
            .iter()
            .find(|address| address.ip().is_ipv4())
            .copied(),
        Some("UseIPv6") => addresses
            .iter()
            .find(|address| address.ip().is_ipv6())
            .copied(),
        Some("UseIPv4v6") => addresses
            .iter()
            .find(|address| address.ip().is_ipv4())
            .or_else(|| addresses.iter().find(|address| address.ip().is_ipv6()))
            .copied(),
        Some("UseIPv6v4") => addresses
            .iter()
            .find(|address| address.ip().is_ipv6())
            .or_else(|| addresses.iter().find(|address| address.ip().is_ipv4()))
            .copied(),
        _ => addresses.first().copied(),
    };

    if address.is_none() && matches!(strategy, Some("UseIPv4" | "UseIPv6")) {
        return Err(CoreError::NoFreedomAddressForDomainStrategy(
            strategy.unwrap().to_owned(),
        ));
    }

    Ok(address)
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
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n")
            .await?;
    }
    client.shutdown().await?;
    Ok(())
}

struct UdpRelayContext {
    source_ip: IpAddr,
    source_port: u16,
    inbound_tag: String,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    dns_hosts: DnsHosts,
    counters: Arc<TrafficCounters>,
    sniff_quic: bool,
}

#[derive(Default)]
struct UdpResponseTasks {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl UdpResponseTasks {
    fn push(&mut self, task: tokio::task::JoinHandle<()>) {
        self.tasks.push(task);
    }
}

impl Drop for UdpResponseTasks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn handle_trojan_udp_relay(
    client: InboundStream,
    accepted: AcceptedInbound,
    context: UdpRelayContext,
) -> Result<(), CoreError> {
    let (mut reader, mut writer) = tokio::io::split(client);
    let (responses, mut received_responses) = mpsc::channel::<UdpPayloadResponse>(32);
    let mut freedom_sockets = HashMap::<(String, u16), Arc<UdpSocket>>::new();
    let mut response_tasks = UdpResponseTasks::default();
    loop {
        tokio::select! {
            packet = read_trojan_udp_packet(&mut reader) => {
                let Some((destination, payload)) = packet? else {
                    return Ok(());
                };
                let mut session = SessionContext::new(context.inbound_tag.clone(), destination.clone())
                    .with_source_ip(context.source_ip)
                    .with_source_port(context.source_port);
                if let Some(user) = accepted.user.as_ref() {
                    session = session.with_user(user.clone());
                }
                if context.sniff_quic && is_quic_initial_packet(&payload) {
                    session = session.with_protocol("quic");
                }
                let outbound_tag = pick_udp_outbound(&context.router, &session, &destination, &context.dns_hosts).await?;
                let outbound = context
                    .outbounds
                    .get(outbound_tag)
                    .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
                context.counters.add_uplink(payload.len() as u64);
                if outbound.protocol == OutboundProtocol::Blackhole {
                    continue;
                }
                if outbound.protocol == OutboundProtocol::Freedom {
                    send_trojan_freedom_udp_payload(
                        &mut freedom_sockets,
                        &mut response_tasks,
                        responses.clone(),
                        outbound,
                        &destination,
                        &payload,
                        &context.dns_hosts,
                    )
                    .await?;
                } else {
                    let response = send_socks_udp_payload_with_dns_hosts(
                        outbound,
                        &destination,
                        &payload,
                        &context.dns_hosts,
                    )
                    .await?;
                    responses.send(response).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Trojan UDP response channel closed")
                    })?;
                }
            }
            response = received_responses.recv() => {
                let Some(response) = response else {
                    return Ok(());
                };
                write_trojan_udp_packet(&mut writer, &response.destination, &response.payload).await?;
                context.counters.add_downlink(response.payload.len() as u64);
            }
        }
    }
}

async fn send_trojan_freedom_udp_payload(
    sockets: &mut HashMap<(String, u16), Arc<UdpSocket>>,
    response_tasks: &mut UdpResponseTasks,
    responses: mpsc::Sender<UdpPayloadResponse>,
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
    dns_hosts: &DnsHosts,
) -> Result<(), CoreError> {
    if outbound_uses_tls(outbound) {
        return Err(CoreError::UnsupportedSocksUdpOutbound(outbound.tag.clone()));
    }
    let destination = freedom_destination_with_dns_hosts(outbound, destination, dns_hosts).await?;
    let key = (destination.host.to_string(), destination.port);
    let socket = match sockets.entry(key) {
        Entry::Occupied(entry) => Arc::clone(entry.get()),
        Entry::Vacant(entry) => {
            let bind_address =
                freedom_udp_bind_addr(&destination, freedom_send_through_ip(outbound));
            let socket = Arc::new(UdpSocket::bind(bind_address).await?);
            socket
                .connect((destination.host.to_string(), destination.port))
                .await?;
            let response_socket = Arc::clone(&socket);
            let response_destination = destination.clone();
            response_tasks.push(tokio::spawn(async move {
                let mut response = vec![0_u8; 65535];
                loop {
                    let Ok(length) = response_socket.recv(&mut response).await else {
                        return;
                    };
                    let payload = response[..length].to_vec();
                    if responses
                        .send(UdpPayloadResponse {
                            destination: response_destination.clone(),
                            payload,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }));
            Arc::clone(entry.insert(socket))
        }
    };
    socket.send(payload).await?;
    Ok(())
}

async fn handle_vless_udp_relay(
    mut client: InboundStream,
    accepted: AcceptedInbound,
    context: UdpRelayContext,
) -> Result<(), CoreError> {
    write_client_prefix(&mut client, &accepted.client_prefix).await?;
    loop {
        let mut length = [0_u8; 2];
        match client.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let payload_len = usize::from(u16::from_be_bytes(length));
        let mut payload = vec![0_u8; payload_len];
        client.read_exact(&mut payload).await?;
        let mut session =
            SessionContext::new(context.inbound_tag.clone(), accepted.destination.clone())
                .with_source_ip(context.source_ip)
                .with_source_port(context.source_port);
        if let Some(user) = accepted.user.as_ref() {
            session = session.with_user(user.clone());
        }
        if context.sniff_quic && is_quic_initial_packet(&payload) {
            session = session.with_protocol("quic");
        }
        let outbound_tag = pick_udp_outbound(
            &context.router,
            &session,
            &accepted.destination,
            &context.dns_hosts,
        )
        .await?;
        let outbound = context
            .outbounds
            .get(outbound_tag)
            .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
        context.counters.add_uplink(payload.len() as u64);
        if outbound.protocol == OutboundProtocol::Blackhole {
            continue;
        }
        let response = send_socks_udp_payload_with_dns_hosts(
            outbound,
            &accepted.destination,
            &payload,
            &context.dns_hosts,
        )
        .await?;
        let response_len = u16::try_from(response.payload.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "VLESS UDP response too large")
        })?;
        client.write_all(&response_len.to_be_bytes()).await?;
        client.write_all(&response.payload).await?;
        context.counters.add_downlink(response.payload.len() as u64);
    }
}

async fn handle_vmess_udp_relay(
    mut client: InboundStream,
    accepted: AcceptedInbound,
    context: UdpRelayContext,
) -> Result<(), CoreError> {
    let mut session = accepted.vmess.ok_or(CoreError::MalformedVmessRequest)?;
    write_vmess_response_header(&mut client, &session, session.response_auth).await?;
    while let Some(payload) = session.reader.read_chunk(&mut client).await? {
        let mut route_session =
            SessionContext::new(context.inbound_tag.clone(), accepted.destination.clone())
                .with_source_ip(context.source_ip)
                .with_source_port(context.source_port);
        if let Some(user) = accepted.user.as_ref() {
            route_session = route_session.with_user(user.clone());
        }
        if context.sniff_quic && is_quic_initial_packet(&payload) {
            route_session = route_session.with_protocol("quic");
        }
        let outbound_tag = pick_udp_outbound(
            &context.router,
            &route_session,
            &accepted.destination,
            &context.dns_hosts,
        )
        .await?;
        let outbound = context
            .outbounds
            .get(outbound_tag)
            .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
        context.counters.add_uplink(payload.len() as u64);
        if outbound.protocol == OutboundProtocol::Blackhole {
            continue;
        }
        let response = send_socks_udp_payload_with_dns_hosts(
            outbound,
            &accepted.destination,
            &payload,
            &context.dns_hosts,
        )
        .await?;
        context.counters.add_downlink(response.payload.len() as u64);
        session
            .writer
            .write_chunk(&mut client, &response.payload)
            .await?;
    }
    session.writer.write_end(&mut client).await?;
    Ok(())
}

async fn handle_socks_udp_associate(
    mut client: InboundStream,
    associate: SocksUdpAssociate,
    allowed_peer_ip: IpAddr,
    context: UdpRelayContext,
) -> Result<(), CoreError> {
    let socket = Arc::new(associate.socket);
    let user = associate.user;
    let mut tcp_probe = [0_u8; 1];
    let mut packet = vec![0_u8; 65535];
    loop {
        tokio::select! {
            result = client.read(&mut tcp_probe) => {
                if result? == 0 {
                    return Ok(());
                }
            }
            result = socket.recv_from(&mut packet) => {
                let (length, peer) = result?;
                if peer.ip() != allowed_peer_ip {
                    continue;
                }
                let Ok(parsed) = parse_socks_udp_packet(&packet[..length]) else {
                    continue;
                };
                let mut session = SessionContext::new(context.inbound_tag.clone(), parsed.destination.clone())
                    .with_source_ip(peer.ip())
                    .with_source_port(peer.port());
                if let Some(user) = user.as_ref() {
                    session = session.with_user(user.clone());
                }
                if context.sniff_quic && is_quic_initial_packet(&parsed.payload) {
                    session = session.with_protocol("quic");
                }
                let outbound_tag = pick_udp_outbound(
                    &context.router,
                    &session,
                    &parsed.destination,
                    &context.dns_hosts,
                )
                .await?;
                let outbound = context
                    .outbounds
                    .get(outbound_tag)
                    .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
                context.counters.add_uplink(parsed.payload.len() as u64);
                if outbound.protocol == OutboundProtocol::Blackhole {
                    continue;
                }
                let outbound = outbound.clone();
                let socket = Arc::clone(&socket);
                let dns_hosts = Arc::clone(&context.dns_hosts);
                let counters = Arc::clone(&context.counters);
                tokio::spawn(async move {
                    match send_socks_udp_payload_with_dns_hosts(
                        &outbound,
                        &parsed.destination,
                        &parsed.payload,
                        &dns_hosts,
                    )
                    .await
                    {
                        Ok(response) => {
                            counters.add_downlink(response.payload.len() as u64);
                            if let Ok(wrapped) = encode_socks_udp_packet(&response.destination, &response.payload) {
                                let _ = socket.send_to(&wrapped, peer).await;
                            }
                        }
                        Err(CoreError::Timeout) => {}
                        Err(error) => {
                            tracing::debug!(%peer, %error, "SOCKS UDP outbound packet failed");
                        }
                    }
                });
            }
        }
    }
}

async fn run_shadowsocks_udp_inbound(
    inbound: InboundConfig,
    socket: UdpSocket,
    router: Arc<Router>,
    outbounds: Arc<HashMap<String, OutboundConfig>>,
    dns_hosts: DnsHosts,
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
            dns_hosts: Arc::clone(&dns_hosts),
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
    dns_hosts: DnsHosts,
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
    let outbound_tag =
        pick_udp_outbound(&context.router, &session, &destination, &context.dns_hosts).await?;
    let outbound = context
        .outbounds
        .get(outbound_tag)
        .ok_or_else(|| CoreError::MissingOutbound(outbound_tag.to_owned()))?;
    context.counters.add_uplink(payload.len() as u64);
    if outbound.protocol == OutboundProtocol::Blackhole {
        return Ok(());
    }
    let response =
        send_socks_udp_payload_with_dns_hosts(outbound, &destination, &payload, &context.dns_hosts)
            .await?;
    let wrapped =
        encrypt_shadowsocks_udp_packet(context.key, &response.destination, &response.payload)?;
    context.socket.send_to(&wrapped, peer).await?;
    context.counters.add_downlink(response.payload.len() as u64);
    Ok(())
}

struct UdpPayloadResponse {
    destination: Destination,
    payload: Vec<u8>,
}

async fn connect_udp_to_host(host: &str, port: u16) -> Result<UdpSocket, CoreError> {
    connect_udp_to_host_with_family(host, port, None).await
}

async fn connect_udp_to_host_with_family(
    host: &str,
    port: u16,
    family: Option<IpAddr>,
) -> Result<UdpSocket, CoreError> {
    let addresses = lookup_host((host, port)).await?;
    let address = pick_udp_upstream_address(addresses, family)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "UDP upstream address not found"))?;
    let bind_address = udp_unspecified_bind_address(address);
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(address).await?;
    Ok(socket)
}

fn pick_udp_upstream_address(
    addresses: impl IntoIterator<Item = SocketAddr>,
    family: Option<IpAddr>,
) -> Option<SocketAddr> {
    match family {
        Some(IpAddr::V4(_)) => addresses.into_iter().find(SocketAddr::is_ipv4),
        Some(IpAddr::V6(_)) => addresses.into_iter().find(SocketAddr::is_ipv6),
        None => addresses.into_iter().next(),
    }
}

fn udp_unspecified_bind_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
async fn send_socks_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let dns_hosts = Arc::new(RuntimeDns::default());
    send_socks_udp_payload_with_dns_hosts(outbound, destination, payload, &dns_hosts).await
}

async fn send_socks_udp_payload_with_dns_hosts(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
    dns_hosts: &DnsHosts,
) -> Result<UdpPayloadResponse, CoreError> {
    if outbound_uses_tls(outbound)
        && !matches!(
            outbound.protocol,
            OutboundProtocol::Socks | OutboundProtocol::Vless | OutboundProtocol::Vmess
        )
    {
        return Err(CoreError::UnsupportedSocksUdpOutbound(outbound.tag.clone()));
    }
    let (target, bind_address) = match outbound.protocol {
        OutboundProtocol::Freedom => {
            let destination =
                freedom_destination_with_dns_hosts(outbound, destination, dns_hosts).await?;
            let bind_address =
                freedom_udp_bind_addr(&destination, freedom_send_through_ip(outbound));
            (
                (destination.host.to_string(), destination.port),
                bind_address,
            )
        }
        OutboundProtocol::Dns => {
            let server = outbound
                .settings
                .as_ref()
                .and_then(|settings| settings.servers.first())
                .ok_or(CoreError::MissingProxyServer)?;
            let socket = connect_udp_to_host(&server.address, server.port).await?;
            timeout(DNS_TIMEOUT, socket.send(payload))
                .await
                .map_err(|_| CoreError::Timeout)??;
            let mut response = vec![0_u8; 65535];
            let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
                .await
                .map_err(|_| CoreError::Timeout)??;
            response.truncate(length);
            return Ok(UdpPayloadResponse {
                destination: destination.clone(),
                payload: response,
            });
        }
        OutboundProtocol::Shadowsocks => {
            return send_shadowsocks_udp_payload(outbound, destination, payload).await;
        }
        OutboundProtocol::Socks => {
            return send_socks_upstream_udp_payload(outbound, destination, payload).await;
        }
        OutboundProtocol::Trojan => {
            return send_trojan_udp_payload(outbound, destination, payload).await;
        }
        OutboundProtocol::Vless => {
            return send_vless_udp_payload(outbound, destination, payload).await;
        }
        OutboundProtocol::Vmess => {
            return send_vmess_udp_payload(outbound, destination, payload).await;
        }
        _ => return Err(CoreError::UnsupportedSocksUdpOutbound(outbound.tag.clone())),
    };
    let socket = UdpSocket::bind(bind_address).await?;
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

async fn send_trojan_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let mut remote = timeout(
        DNS_TIMEOUT,
        connect_trojan_upstream_with_command(outbound, destination, 0x03),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    timeout(
        DNS_TIMEOUT,
        write_trojan_udp_packet(&mut remote, destination, payload),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    let response = timeout(DNS_TIMEOUT, read_trojan_udp_packet(&mut remote))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let Some((response_destination, response_payload)) = response else {
        return Err(CoreError::Timeout);
    };
    Ok(UdpPayloadResponse {
        destination: response_destination,
        payload: response_payload,
    })
}

async fn send_vless_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let mut remote = timeout(
        DNS_TIMEOUT,
        connect_vless_upstream_with_command(outbound, destination, 0x02),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    timeout(DNS_TIMEOUT, write_vless_udp_frame(&mut remote, payload))
        .await
        .map_err(|_| CoreError::Timeout)??;
    let response = timeout(DNS_TIMEOUT, read_vless_udp_frame(&mut remote))
        .await
        .map_err(|_| CoreError::Timeout)??
        .unwrap_or_default();
    Ok(UdpPayloadResponse {
        destination: destination.clone(),
        payload: response,
    })
}

async fn send_vmess_udp_payload(
    outbound: &OutboundConfig,
    destination: &Destination,
    payload: &[u8],
) -> Result<UdpPayloadResponse, CoreError> {
    let (mut remote, mut session) = timeout(
        DNS_TIMEOUT,
        connect_vmess_upstream_with_command(outbound, destination, 2),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    timeout(
        DNS_TIMEOUT,
        session.writer.write_chunk(&mut remote, payload),
    )
    .await
    .map_err(|_| CoreError::Timeout)??;
    let response = timeout(DNS_TIMEOUT, session.reader.read_chunk(&mut remote))
        .await
        .map_err(|_| CoreError::Timeout)??
        .unwrap_or_default();
    timeout(DNS_TIMEOUT, session.writer.write_end(&mut remote))
        .await
        .map_err(|_| CoreError::Timeout)??;
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
    connect_proxy_stream_with_source(outbound, None).await
}

async fn connect_proxy_stream_with_source(
    outbound: &OutboundConfig,
    source_ip: Option<IpAddr>,
) -> Result<OutboundStream, CoreError> {
    let server = outbound_server(outbound)?;
    let host =
        DestinationHost::parse(&server.address).map_err(|_| CoreError::MissingProxyServer)?;
    let destination = Destination::tcp(host, server.port);
    connect_outbound_stream_with_source(outbound, &destination, source_ip).await
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

    let socket = connect_udp_to_host(&server.address, server.port).await?;
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
    let relay = timeout(DEFAULT_HANDSHAKE_TIMEOUT, async {
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

    let (relay_host, relay_family) = match relay.host {
        DestinationHost::Ip(ip) if ip.is_unspecified() => (server.address.clone(), Some(ip)),
        _ => (relay.host.to_string(), None),
    };
    let socket = connect_udp_to_host_with_family(&relay_host, relay.port, relay_family).await?;
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
    Ok(Destination {
        host,
        port,
        network: dokodemo_network(settings),
    })
}

fn dokodemo_network(settings: &xrs_config::InboundSettings) -> Network {
    if settings.network.as_deref().is_some_and(|network| {
        network
            .split(',')
            .map(str::trim)
            .any(|network| network == "udp")
    }) {
        Network::Udp
    } else {
        Network::Tcp
    }
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
    let matched_client = settings
        .clients
        .iter()
        .find(|client| {
            client
                .password
                .as_deref()
                .is_some_and(|client_password| password == trojan_password_hash(client_password))
        })
        .ok_or(CoreError::InvalidTrojanPassword)?;

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    let network = match command[0] {
        0x01 => Network::Tcp,
        0x03 => Network::Udp,
        command => return Err(CoreError::UnsupportedTrojanCommand(command)),
    };

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

    let mut accepted = AcceptedInbound::new(Destination {
        host,
        port,
        network,
    });
    accepted.user = matched_client.email.clone();
    Ok(accepted)
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

async fn read_trojan_udp_packet<S>(
    stream: &mut S,
) -> Result<Option<(Destination, Vec<u8>)>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut address_type = [0_u8; 1];
    match stream.read_exact(&mut address_type).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let host = read_socks_host(stream, address_type[0])
        .await
        .map_err(|error| match error {
            CoreError::UnsupportedSocksAddress(address_type) => {
                CoreError::UnsupportedTrojanAddress(address_type)
            }
            error => error,
        })?;
    let port = read_port(stream).await?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    read_trojan_crlf(stream).await?;
    let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut payload).await?;
    Ok(Some((
        Destination {
            host,
            port,
            network: Network::Udp,
        },
        payload,
    )))
}

async fn write_trojan_udp_packet<S>(
    stream: &mut S,
    destination: &Destination,
    payload: &[u8],
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    match &destination.host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            stream.write_all(&[0x01]).await?;
            stream.write_all(&ip.octets()).await?;
        }
        DestinationHost::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| CoreError::SocksDomainTooLong)?;
            stream.write_all(&[0x03, len]).await?;
            stream.write_all(domain.as_bytes()).await?;
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            stream.write_all(&[0x04]).await?;
            stream.write_all(&ip.octets()).await?;
        }
    }
    stream.write_all(&destination.port.to_be_bytes()).await?;
    let length = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Trojan UDP payload too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn connect_trojan_upstream(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<OutboundStream, CoreError> {
    connect_trojan_upstream_with_command(outbound, destination, 0x01).await
}

async fn connect_trojan_upstream_with_command(
    outbound: &OutboundConfig,
    destination: &Destination,
    command: u8,
) -> Result<OutboundStream, CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    let password = server
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or(CoreError::InvalidTrojanPassword)?;
    let mut remote = connect_proxy_stream(outbound).await?;
    write_trojan_request(&mut remote, password, command, destination).await?;
    Ok(remote)
}

async fn write_trojan_request<S>(
    stream: &mut S,
    password: &str,
    command: u8,
    destination: &Destination,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&trojan_password_hash(password)).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(&[command]).await?;
    write_trojan_host(stream, &destination.host).await?;
    stream.write_all(&destination.port.to_be_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

async fn write_trojan_host<S>(stream: &mut S, host: &DestinationHost) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    match host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            stream.write_all(&[0x01]).await?;
            stream.write_all(&ip.octets()).await?;
        }
        DestinationHost::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| CoreError::SocksDomainTooLong)?;
            stream.write_all(&[0x03, len]).await?;
            stream.write_all(domain.as_bytes()).await?;
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            stream.write_all(&[0x04]).await?;
            stream.write_all(&ip.octets()).await?;
        }
    }
    Ok(())
}

async fn connect_vless_upstream(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<OutboundStream, CoreError> {
    connect_vless_upstream_with_command(outbound, destination, 0x01).await
}

async fn connect_vless_upstream_with_command(
    outbound: &OutboundConfig,
    destination: &Destination,
    command: u8,
) -> Result<OutboundStream, CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    let id = server
        .id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or(CoreError::InvalidVlessClient)?;
    let mut remote = connect_proxy_stream(outbound).await?;
    write_vless_request(&mut remote, &id, command, destination).await?;
    let mut response = [0_u8; 2];
    remote.read_exact(&mut response).await?;
    if response != [0, 0] {
        return Err(CoreError::MalformedVlessRequest);
    }
    Ok(remote)
}

async fn write_vless_request<S>(
    stream: &mut S,
    id: &Uuid,
    command: u8,
    destination: &Destination,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[0]).await?;
    stream.write_all(id.as_bytes()).await?;
    stream.write_all(&[0, command]).await?;
    stream.write_all(&destination.port.to_be_bytes()).await?;
    write_vless_host(stream, &destination.host).await?;
    Ok(())
}

async fn write_vless_host<S>(stream: &mut S, host: &DestinationHost) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    match host {
        DestinationHost::Ip(IpAddr::V4(ip)) => {
            stream.write_all(&[0x01]).await?;
            stream.write_all(&ip.octets()).await?;
        }
        DestinationHost::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| CoreError::SocksDomainTooLong)?;
            stream.write_all(&[0x02, len]).await?;
            stream.write_all(domain.as_bytes()).await?;
        }
        DestinationHost::Ip(IpAddr::V6(ip)) => {
            stream.write_all(&[0x03]).await?;
            stream.write_all(&ip.octets()).await?;
        }
    }
    Ok(())
}

async fn write_vless_udp_frame<S>(stream: &mut S, payload: &[u8]) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VLESS UDP payload too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_vless_udp_frame<S>(stream: &mut S) -> Result<Option<Vec<u8>>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut payload).await?;
    Ok(Some(payload))
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
    let matched_client = settings
        .clients
        .iter()
        .find(|client| {
            client
                .id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .is_some_and(|id| id.as_bytes() == &client_id)
        })
        .ok_or(CoreError::InvalidVlessClient)?;

    let mut option_length = [0_u8; 1];
    stream.read_exact(&mut option_length).await?;
    let mut options = vec![0_u8; usize::from(option_length[0])];
    stream.read_exact(&mut options).await?;

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    let network = match command[0] {
        0x01 => Network::Tcp,
        0x02 => Network::Udp,
        command => return Err(CoreError::UnsupportedVlessCommand(command)),
    };

    let port = read_port(stream).await?;
    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    let host = read_vless_host(stream, address_type[0]).await?;

    Ok(AcceptedInbound {
        destination: Destination {
            host,
            port,
            network,
        },
        routing_destination: None,
        remote_prefix: Vec::new(),
        client_prefix: vec![version[0], 0],
        shadowsocks: None,
        vmess: None,
        socks_udp: None,
        user: matched_client.email.clone(),
        protocol: None,
        attributes: HashMap::new(),
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
    user: Option<String>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessBodySecurity {
    None,
    Aes128Gcm,
    Chacha20Poly1305,
}

#[derive(Clone)]
struct VmessReader {
    key: [u8; 16],
    iv: [u8; 16],
    nonce: u32,
    masked: bool,
    security: VmessBodySecurity,
}

impl VmessReader {
    async fn read_chunk<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let nonce = self.next_nonce()?;
        let mut len_bytes = [0_u8; 2];
        match stream.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if self.masked {
            vmess_mask_length(&mut len_bytes, &self.iv, nonce);
        }
        let len = u16::from_be_bytes(len_bytes) as usize;
        if len == 0 {
            return Ok(None);
        }
        if len > VMESS_MAX_CHUNK + 16 {
            return Err(CoreError::MalformedVmessRequest);
        }
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await?;
        match self.security {
            VmessBodySecurity::None => {}
            VmessBodySecurity::Aes128Gcm | VmessBodySecurity::Chacha20Poly1305 => {
                payload =
                    vmess_body_aead_decrypt(self.security, &self.key, &self.iv, nonce, &payload)?;
                if payload.is_empty() {
                    return Ok(None);
                }
            }
        }
        Ok(Some(payload))
    }

    fn next_nonce(&mut self) -> Result<u32, CoreError> {
        if self.security != VmessBodySecurity::None && self.nonce > u16::MAX as u32 {
            return Err(CoreError::MalformedVmessRequest);
        }
        let nonce = self.nonce;
        self.nonce = self.nonce.wrapping_add(1);
        Ok(nonce)
    }
}

#[derive(Clone)]
struct VmessWriter {
    key: [u8; 16],
    iv: [u8; 16],
    nonce: u32,
    masked: bool,
    security: VmessBodySecurity,
}

impl VmessWriter {
    async fn write_chunk<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        payload: &[u8],
    ) -> Result<(), CoreError> {
        for chunk in payload.chunks(VMESS_MAX_CHUNK) {
            let nonce = self.next_nonce()?;
            let payload = match self.security {
                VmessBodySecurity::None => chunk.to_vec(),
                VmessBodySecurity::Aes128Gcm | VmessBodySecurity::Chacha20Poly1305 => {
                    vmess_body_aead_encrypt(self.security, &self.key, &self.iv, nonce, chunk)?
                }
            };
            let mut len = u16::try_from(payload.len())
                .map_err(|_| CoreError::MalformedVmessRequest)?
                .to_be_bytes();
            if self.masked {
                vmess_mask_length(&mut len, &self.iv, nonce);
            }
            stream.write_all(&len).await?;
            stream.write_all(&payload).await?;
        }
        Ok(())
    }

    async fn write_end<S: AsyncWrite + Unpin>(&mut self, stream: &mut S) -> Result<(), CoreError> {
        if matches!(
            self.security,
            VmessBodySecurity::Aes128Gcm | VmessBodySecurity::Chacha20Poly1305
        ) {
            let nonce = self.next_nonce()?;
            let payload = vmess_body_aead_encrypt(self.security, &self.key, &self.iv, nonce, &[])?;
            let mut len = u16::try_from(payload.len())
                .map_err(|_| CoreError::MalformedVmessRequest)?
                .to_be_bytes();
            if self.masked {
                vmess_mask_length(&mut len, &self.iv, nonce);
            }
            stream.write_all(&len).await?;
            stream.write_all(&payload).await?;
            return Ok(());
        }
        let nonce = self.next_nonce()?;
        let mut len = [0_u8; 2];
        if self.masked {
            vmess_mask_length(&mut len, &self.iv, nonce);
        }
        stream.write_all(&len).await?;
        Ok(())
    }

    fn next_nonce(&mut self) -> Result<u32, CoreError> {
        if self.security != VmessBodySecurity::None && self.nonce > u16::MAX as u32 {
            return Err(CoreError::MalformedVmessRequest);
        }
        let nonce = self.nonce;
        self.nonce = self.nonce.wrapping_add(1);
        Ok(nonce)
    }
}

struct VmessRequest {
    destination: Destination,
    response_auth: u8,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    options: u8,
    security: VmessBodySecurity,
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

fn vmess_body_nonce(iv: &[u8; 16], nonce: u32) -> [u8; 12] {
    let mut out = [0_u8; 12];
    out.copy_from_slice(&iv[..12]);
    out[..2].copy_from_slice(&(nonce as u16).to_be_bytes());
    out
}

fn vmess_body_aead_encrypt(
    security: VmessBodySecurity,
    key: &[u8; 16],
    iv: &[u8; 16],
    nonce: u32,
    plain: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let nonce = vmess_body_nonce(iv, nonce);
    match security {
        VmessBodySecurity::None => Ok(plain.to_vec()),
        VmessBodySecurity::Aes128Gcm => Aes128Gcm::new(key.into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &[],
                },
            )
            .map_err(|_| CoreError::VmessDecryptFailed),
        VmessBodySecurity::Chacha20Poly1305 => {
            ChaCha20Poly1305::new((&vmess_chacha20_key(key)).into())
                .encrypt((&nonce).into(), plain)
                .map_err(|_| CoreError::VmessDecryptFailed)
        }
    }
}

fn vmess_body_aead_decrypt(
    security: VmessBodySecurity,
    key: &[u8; 16],
    iv: &[u8; 16],
    nonce: u32,
    encrypted: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let nonce = vmess_body_nonce(iv, nonce);
    match security {
        VmessBodySecurity::None => Ok(encrypted.to_vec()),
        VmessBodySecurity::Aes128Gcm => Aes128Gcm::new(key.into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: encrypted,
                    aad: &[],
                },
            )
            .map_err(|_| CoreError::VmessDecryptFailed),
        VmessBodySecurity::Chacha20Poly1305 => {
            ChaCha20Poly1305::new((&vmess_chacha20_key(key)).into())
                .decrypt((&nonce).into(), encrypted)
                .map_err(|_| CoreError::VmessDecryptFailed)
        }
    }
}

fn vmess_chacha20_key(key: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key);
    let second = Md5::digest(first);
    let mut out = [0_u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
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
    let (request, client_id) = read_vmess_request(stream, &clients, Some(replay_cache)).await?;
    let user = settings
        .clients
        .iter()
        .find(|client| {
            client
                .id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .is_some_and(|id| id == client_id)
        })
        .and_then(|client| client.email.clone());
    let response_key = vmess_response_derive(&request.body_key);
    let response_iv = vmess_response_derive(&request.body_iv);
    let masked = request.options & VMESS_OPTION_CHUNK_MASKING != 0;
    Ok(AcceptedInbound {
        destination: request.destination,
        routing_destination: None,
        remote_prefix: Vec::new(),
        client_prefix: Vec::new(),
        shadowsocks: None,
        vmess: Some(VmessSession {
            reader: VmessReader {
                key: request.body_key,
                iv: request.body_iv,
                nonce: 0,
                masked,
                security: request.security,
            },
            writer: VmessWriter {
                key: response_key,
                iv: response_iv,
                nonce: 0,
                masked,
                security: request.security,
            },
            response_auth: request.response_auth,
        }),
        socks_udp: None,
        user,
        protocol: None,
        attributes: HashMap::new(),
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
    let mut body_key = [0_u8; 16];
    body_key.copy_from_slice(&data[17..33]);
    let response_auth = data[33];
    let options = data[34];
    let padding_security = data[35];
    let padding_len = usize::from(padding_security >> 4);
    let security = match padding_security & 0x0f {
        VMESS_SECURITY_NONE => VmessBodySecurity::None,
        VMESS_SECURITY_AES_128_GCM => VmessBodySecurity::Aes128Gcm,
        VMESS_SECURITY_CHACHA20_POLY1305 => VmessBodySecurity::Chacha20Poly1305,
        security => return Err(CoreError::UnsupportedVmessSecurity(security)),
    };
    if data[36] != 0 {
        return Err(CoreError::MalformedVmessRequest);
    }
    let command = data[37];
    let network = match command {
        1 => Network::Tcp,
        2 => Network::Udp,
        command => return Err(CoreError::UnsupportedVmessCommand(command)),
    };
    let port = u16::from_be_bytes([data[38], data[39]]);
    let (host, offset) = parse_vmess_host(data, 40)?;
    if offset + padding_len + 4 != data.len() {
        return Err(CoreError::MalformedVmessRequest);
    }
    Ok(VmessRequest {
        destination: Destination {
            host,
            port,
            network,
        },
        response_auth,
        body_key,
        body_iv,
        options,
        security,
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

#[cfg(test)]
fn build_vmess_request(
    id: &Uuid,
    destination: &Destination,
) -> Result<(Vec<u8>, VmessSession), CoreError> {
    build_vmess_request_with_command_and_security(id, destination, 1, VmessBodySecurity::None)
}

#[cfg(test)]
fn build_vmess_udp_request(
    id: &Uuid,
    destination: &Destination,
) -> Result<(Vec<u8>, VmessSession), CoreError> {
    build_vmess_request_with_command(id, destination, 2)
}

#[cfg(test)]
fn build_vmess_request_with_command(
    id: &Uuid,
    destination: &Destination,
    command: u8,
) -> Result<(Vec<u8>, VmessSession), CoreError> {
    build_vmess_request_with_command_and_security(id, destination, command, VmessBodySecurity::None)
}

fn build_vmess_request_with_command_and_security(
    id: &Uuid,
    destination: &Destination,
    command: u8,
    security: VmessBodySecurity,
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
    instruction.push(match security {
        VmessBodySecurity::None => VMESS_SECURITY_NONE,
        VmessBodySecurity::Aes128Gcm => VMESS_SECURITY_AES_128_GCM,
        VmessBodySecurity::Chacha20Poly1305 => VMESS_SECURITY_CHACHA20_POLY1305,
    });
    instruction.push(0);
    instruction.push(command);
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
    let response_key = vmess_response_derive(&body_key);
    let response_iv = vmess_response_derive(&body_iv);
    Ok((
        out,
        VmessSession {
            reader: VmessReader {
                key: response_key,
                iv: response_iv,
                nonce: 0,
                masked: true,
                security,
            },
            writer: VmessWriter {
                key: body_key,
                iv: body_iv,
                nonce: 0,
                masked: true,
                security,
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
    connect_vmess_upstream_with_command(outbound, destination, 1).await
}

async fn connect_vmess_upstream_with_command(
    outbound: &OutboundConfig,
    destination: &Destination,
    command: u8,
) -> Result<(OutboundStream, VmessSession), CoreError> {
    let server = outbound
        .settings
        .as_ref()
        .and_then(|s| s.servers.first())
        .ok_or(CoreError::MissingProxyServer)?;
    let security = vmess_server_security(server)?;
    let id = server
        .id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or(CoreError::MissingVmessSettings)?;
    let mut remote = connect_proxy_stream(outbound).await?;
    let (header, session) =
        build_vmess_request_with_command_and_security(&id, destination, command, security)?;
    remote.write_all(&header).await?;
    read_vmess_response_header(&mut remote, &session).await?;
    Ok((remote, session))
}

fn vmess_server_security(
    server: &xrs_config::ProxyServerConfig,
) -> Result<VmessBodySecurity, CoreError> {
    match server.security.as_deref().unwrap_or("auto") {
        "" | "none" => Ok(VmessBodySecurity::None),
        "aes-128-gcm" | "auto" => Ok(VmessBodySecurity::Aes128Gcm),
        "chacha20-poly1305" => Ok(VmessBodySecurity::Chacha20Poly1305),
        _ => Err(CoreError::UnsupportedVmessSecurity(0)),
    }
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

fn socks_udp_enabled(inbound: &InboundConfig) -> bool {
    inbound
        .settings
        .as_ref()
        .is_some_and(|settings| settings.udp == Some(true))
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
    let user = if accounts.is_empty() {
        if !methods.contains(&0x00) {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(CoreError::UnsupportedSocksMethod);
        }
        stream.write_all(&[0x05, 0x00]).await?;
        None
    } else {
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(CoreError::UnsupportedSocksMethod);
        }
        stream.write_all(&[0x05, 0x02]).await?;
        Some(accept_socks5_password_auth(stream, accounts).await?)
    };

    let request = read_socks_request(stream).await?;
    match request.command {
        0x01 => {
            write_socks_success(stream, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
            let mut accepted = AcceptedInbound::new(request.destination);
            accepted.user = user;
            Ok(accepted)
        }
        0x03 if socks_udp_enabled(inbound) => {
            let listen = inbound
                .listen
                .unwrap_or_else(|| "127.0.0.1".parse().expect("valid loopback"));
            let socket = UdpSocket::bind(SocketAddr::new(listen, 0)).await?;
            let bind_addr = socket.local_addr()?;
            write_socks_success(stream, bind_addr).await?;
            let mut accepted = AcceptedInbound::new(request.destination);
            accepted.socks_udp = Some(SocksUdpAssociate {
                socket,
                user: user.clone(),
            });
            accepted.user = user;
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
) -> Result<String, CoreError>
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
    if let Some(account) = accounts
        .iter()
        .find(|account| account.user.as_bytes() == username && account.pass.as_bytes() == password)
    {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(account.user.clone())
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
    let user = if accounts.is_empty() {
        None
    } else if let Some(user) = http_proxy_auth_user(header, accounts) {
        Some(user)
    } else {
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(CoreError::ProxyAuthenticationFailed);
    };
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
        let mut accepted = AcceptedInbound::new(destination);
        accepted.user = user;
        return Ok(accepted);
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
    remote_prefix.extend_from_slice(b"\r\n");
    for line in header[line_end + 2..].split_inclusive("\r\n") {
        if line == "\r\n" {
            remote_prefix.extend_from_slice(line.as_bytes());
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            remote_prefix.extend_from_slice(line.as_bytes());
            continue;
        };
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        remote_prefix.extend_from_slice(line.as_bytes());
    }

    Ok(AcceptedInbound {
        destination,
        routing_destination: None,
        remote_prefix,
        client_prefix: Vec::new(),
        shadowsocks: None,
        vmess: None,
        socks_udp: None,
        user,
        protocol: None,
        attributes: HashMap::new(),
    })
}

fn inbound_sniffs_http(inbound: &InboundConfig) -> bool {
    inbound.sniffing.as_ref().is_some_and(|sniffing| {
        sniffing.enabled && sniffing.dest_override.iter().any(|value| value == "http")
    })
}

fn inbound_sniffs_tls(inbound: &InboundConfig) -> bool {
    inbound.sniffing.as_ref().is_some_and(|sniffing| {
        sniffing.enabled && sniffing.dest_override.iter().any(|value| value == "tls")
    })
}

fn inbound_sniffs_quic(inbound: &InboundConfig) -> bool {
    inbound.sniffing.as_ref().is_some_and(|sniffing| {
        sniffing.enabled && sniffing.dest_override.iter().any(|value| value == "quic")
    })
}

fn inbound_sniffing_route_only(inbound: &InboundConfig) -> bool {
    inbound
        .sniffing
        .as_ref()
        .is_some_and(|sniffing| sniffing.enabled && sniffing.route_only)
}

fn inbound_sniffing_metadata_only(inbound: &InboundConfig) -> bool {
    inbound
        .sniffing
        .as_ref()
        .is_some_and(|sniffing| sniffing.enabled && sniffing.metadata_only)
}

fn inbound_sniffing_domains_excluded(inbound: &InboundConfig) -> Vec<String> {
    inbound
        .sniffing
        .as_ref()
        .filter(|sniffing| sniffing.enabled)
        .map(|sniffing| sniffing.domains_excluded.clone())
        .unwrap_or_default()
}

fn is_quic_initial_packet(payload: &[u8]) -> bool {
    if payload.first().is_none_or(|first| first & 0xf0 != 0xc0) || payload.len() < 7 {
        return false;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false;
    }
    let destination_connection_id_len = payload[5] as usize;
    if destination_connection_id_len == 0 || destination_connection_id_len > 20 {
        return false;
    }
    let source_connection_id_len_offset = 6 + destination_connection_id_len;
    let Some(&source_connection_id_len) = payload.get(source_connection_id_len_offset) else {
        return false;
    };
    let source_connection_id_len = source_connection_id_len as usize;
    if source_connection_id_len > 20 {
        return false;
    }
    let token_len_offset = source_connection_id_len_offset + 1 + source_connection_id_len;
    let Some(token_len_slice) = payload.get(token_len_offset..) else {
        return false;
    };
    let Some((token_len, token_len_size)) = quic_varint(token_len_slice) else {
        return false;
    };
    let Ok(token_len) = usize::try_from(token_len) else {
        return false;
    };
    let Some(packet_len_offset) = token_len_offset
        .checked_add(token_len_size)
        .and_then(|offset| offset.checked_add(token_len))
    else {
        return false;
    };
    let Some(packet_len_slice) = payload.get(packet_len_offset..) else {
        return false;
    };
    let Some((packet_len, packet_len_size)) = quic_varint(packet_len_slice) else {
        return false;
    };
    let Ok(packet_len) = usize::try_from(packet_len) else {
        return false;
    };
    if packet_len == 0 {
        return false;
    }
    let Some(packet_end) = packet_len_offset
        .checked_add(packet_len_size)
        .and_then(|offset| offset.checked_add(packet_len))
    else {
        return false;
    };
    payload.len() >= packet_end
}

fn quic_varint(payload: &[u8]) -> Option<(u64, usize)> {
    let first = *payload.first()?;
    let len = 1_usize << (first >> 6);
    if payload.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &payload[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

async fn sniff_http_destination<S>(
    stream: &mut S,
    accepted: &mut AcceptedInbound,
    route_only: bool,
    rewrite_destination: bool,
    domains_excluded: &[String],
) -> Result<(), CoreError>
where
    S: AsyncRead + Unpin,
{
    let request =
        read_http_header_with_prefix(stream, std::mem::take(&mut accepted.remote_prefix)).await?;
    let header = str::from_utf8(&request).map_err(|_| CoreError::InvalidHttpTarget)?;
    let mut request_line = header.lines().next().unwrap_or_default().split_whitespace();
    if let Some(method) = request_line.next() {
        accepted
            .attributes
            .insert(":method".to_owned(), method.to_owned());
    }
    if let Some(path) = request_line.next() {
        accepted
            .attributes
            .insert(":path".to_owned(), path.to_owned());
    }
    accepted.protocol = Some("http".to_owned());
    let host = header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("Host").then(|| value.trim())
    });
    let Some(host) = host.filter(|host| !host.is_empty()) else {
        accepted.remote_prefix = request;
        return Ok(());
    };
    let host_without_port = split_http_host_port(host, Some(accepted.destination.port))?.0;
    apply_sniffed_host(
        accepted,
        host_without_port,
        route_only,
        rewrite_destination,
        domains_excluded,
    );
    accepted.remote_prefix = request;
    Ok(())
}

async fn sniff_tls_destination<S>(
    stream: &mut S,
    accepted: &mut AcceptedInbound,
    route_only: bool,
    rewrite_destination: bool,
    domains_excluded: &[String],
) -> Result<bool, CoreError>
where
    S: AsyncRead + Unpin,
{
    let client_hello = read_possible_tls_record(stream).await?;
    if !is_tls_client_hello(&client_hello) {
        accepted.remote_prefix = client_hello;
        return Ok(false);
    }
    accepted.protocol = Some("tls".to_owned());
    if let Some(server_name) = parse_tls_client_hello_sni(&client_hello) {
        apply_sniffed_host(
            accepted,
            DestinationHost::Domain(server_name),
            route_only,
            rewrite_destination,
            domains_excluded,
        );
    }
    accepted.remote_prefix = client_hello;
    Ok(true)
}

fn apply_sniffed_host(
    accepted: &mut AcceptedInbound,
    host: DestinationHost,
    route_only: bool,
    rewrite_destination: bool,
    domains_excluded: &[String],
) {
    if sniffed_host_is_excluded(&host, domains_excluded) {
        return;
    }
    if route_only {
        accepted.routing_destination = Some(Destination {
            host,
            port: accepted.destination.port,
            network: accepted.destination.network,
        });
    } else if rewrite_destination {
        accepted.destination.host = host;
    }
}

fn sniffed_host_is_excluded(host: &DestinationHost, domains_excluded: &[String]) -> bool {
    let DestinationHost::Domain(domain) = host else {
        return false;
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domains_excluded
        .iter()
        .any(|excluded| sniffed_domain_matches_exclusion(&domain, excluded))
}

fn sniffed_domain_matches_exclusion(domain: &str, excluded: &str) -> bool {
    let excluded = excluded.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(full) = excluded.strip_prefix("full:") {
        domain == full
    } else if let Some(suffix) = excluded.strip_prefix("domain:") {
        sniffed_domain_matches_suffix(domain, suffix)
    } else if let Some(keyword) = excluded.strip_prefix("keyword:") {
        domain.contains(keyword)
    } else if let Some(pattern) = excluded.strip_prefix("regexp:") {
        Regex::new(pattern).is_ok_and(|regex| regex.is_match(domain))
    } else if let Some(name) = excluded.strip_prefix("geosite:") {
        match name {
            "private" => sniffed_domain_matches_private_geosite(domain),
            "cn" => sniffed_domain_matches_cn_geosite(domain),
            _ => false,
        }
    } else {
        sniffed_domain_matches_suffix(domain, &excluded)
    }
}

fn sniffed_domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

fn sniffed_domain_matches_cn_geosite(domain: &str) -> bool {
    ["baidu.com", "qq.com", "taobao.com"]
        .iter()
        .any(|suffix| sniffed_domain_matches_suffix(domain, suffix))
}

fn sniffed_domain_matches_private_geosite(domain: &str) -> bool {
    const FULL: &[&str] = &[
        "instant.arubanetworks.com",
        "setmeup.arubanetworks.com",
        "asusrouter.com",
        "router.asus.com",
        "www.asusrouter.com",
        "oasisauth.h3c.com",
        "routerlogin.com",
        "www.routerlogin.com",
        "tplogin.cn",
        "miwifi.com",
        "www.miwifi.com",
        "local.adguard.org",
    ];
    const SUFFIX: &[&str] = &[
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
        "2.0.192.in-addr.arpa",
        "10.in-addr.arpa",
        "100.51.198.in-addr.arpa",
        "113.0.203.in-addr.arpa",
        "127.in-addr.arpa",
        "168.192.in-addr.arpa",
        "254.169.in-addr.arpa",
        "255.255.255.255.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "8.b.d.0.1.0.0.2.ip6.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
        "d.f.ip6.arpa",
        "hiwifi.com",
        "leike.cc",
        "my.router",
        "peiluyou.com",
        "phicomm.me",
        "router.ctc",
        "tendawifi.com",
        "tplinkwifi.net",
        "zte.home",
        "plex.direct",
        "localhost.sec.qq.com",
        "localhost.ptlogin2.qq.com",
        "ts.net",
        "kis.v2.scr.kaspersky-labs.com",
    ];

    FULL.contains(&domain)
        || SUFFIX
            .iter()
            .any(|suffix| sniffed_domain_matches_suffix(domain, suffix))
        || sniffed_domain_matches_private_reverse_dns_range(domain)
        || sniffed_domain_is_dotless(domain)
}

fn sniffed_domain_matches_private_reverse_dns_range(domain: &str) -> bool {
    if let Some(value) = domain.strip_suffix(".172.in-addr.arpa") {
        return value
            .rsplit('.')
            .next()
            .and_then(|octet| octet.parse::<u8>().ok())
            .is_some_and(|octet| (16..=31).contains(&octet));
    }
    if let Some(value) = domain.strip_suffix(".100.in-addr.arpa") {
        return value
            .rsplit('.')
            .next()
            .and_then(|octet| octet.parse::<u8>().ok())
            .is_some_and(|octet| (64..=127).contains(&octet));
    }
    false
}

fn sniffed_domain_is_dotless(domain: &str) -> bool {
    let mut chars = domain.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    !domain.contains('.')
        && domain.len() <= 63
        && first.is_ascii_lowercase()
        && domain.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && domain.ends_with(|character: char| {
            character.is_ascii_lowercase() || character.is_ascii_digit()
        })
}

async fn read_possible_tls_record<S>(stream: &mut S) -> Result<Vec<u8>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x16 || !matches!(header[1], 0x03) || header[2] > 0x04 {
        return Ok(header.to_vec());
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > 16_384 {
        return Ok(header.to_vec());
    }
    let mut record = Vec::with_capacity(header.len() + length);
    record.extend_from_slice(&header);
    record.resize(header.len() + length, 0);
    stream.read_exact(&mut record[header.len()..]).await?;
    Ok(record)
}

fn is_tls_client_hello(record: &[u8]) -> bool {
    if record.len() < 9 || record[0] != 0x16 {
        return false;
    }
    let record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record.len() != 5 + record_len {
        return false;
    }
    let handshake = &record[5..];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return false;
    }
    let handshake_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    handshake.len() >= 4 + handshake_len
}

fn parse_tls_client_hello_sni(record: &[u8]) -> Option<String> {
    if !is_tls_client_hello(record) {
        return None;
    }
    let handshake = &record[5..];
    let handshake_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    let body = handshake.get(4..4 + handshake_len)?;
    parse_tls_client_hello_body_sni(body)
}

fn parse_tls_client_hello_body_sni(body: &[u8]) -> Option<String> {
    let mut cursor = 34;
    let session_id_len = usize::from(*body.get(cursor)?);
    cursor += 1 + session_id_len;
    let cipher_suites_len = usize::from(u16::from_be_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2 + cipher_suites_len;
    let compression_methods_len = usize::from(*body.get(cursor)?);
    cursor += 1 + compression_methods_len;
    let extensions_len = usize::from(u16::from_be_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }
    while cursor + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        cursor += 4;
        let extension_end = cursor.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == 0x0000 {
            return parse_tls_sni_extension(&body[cursor..extension_end]);
        }
        cursor = extension_end;
    }
    None
}

fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
    let list_len = usize::from(u16::from_be_bytes([
        *extension.first()?,
        *extension.get(1)?,
    ]));
    let mut cursor = 2_usize;
    let list_end = cursor.checked_add(list_len)?;
    if list_end > extension.len() {
        return None;
    }
    while cursor + 3 <= list_end {
        let name_type = extension[cursor];
        let name_len = usize::from(u16::from_be_bytes([
            extension[cursor + 1],
            extension[cursor + 2],
        ]));
        cursor += 3;
        let name_end = cursor.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 {
            let name = str::from_utf8(&extension[cursor..name_end]).ok()?;
            return (!name.is_empty()).then(|| name.trim_end_matches('.').to_ascii_lowercase());
        }
        cursor = name_end;
    }
    None
}

fn http_proxy_auth_user(
    header: &str,
    accounts: &[xrs_config::InboundAccountConfig],
) -> Option<String> {
    header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("Proxy-Authorization") {
            return None;
        }
        let value = value.trim_start();
        let (scheme, encoded) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return None;
        }
        let decoded = decode_base64(encoded.trim())?;
        accounts.iter().find_map(|account| {
            let expected = format!("{}:{}", account.user, account.pass);
            (decoded == expected.as_bytes()).then(|| account.user.clone())
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
    read_http_header_with_prefix(stream, Vec::new()).await
}

async fn read_http_header_with_prefix<S>(
    stream: &mut S,
    prefix: Vec<u8>,
) -> Result<Vec<u8>, CoreError>
where
    S: AsyncRead + Unpin,
{
    let mut request = prefix;
    let mut byte = [0_u8; 1];
    let mut complete = request.ends_with(b"\r\n\r\n");
    while !complete && request.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
        complete = request.ends_with(b"\r\n\r\n");
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

fn parse_http_absolute_target(target: &str) -> Result<(Destination, String), CoreError> {
    let rest = target
        .strip_prefix("http://")
        .ok_or(CoreError::UnsupportedHttpRequest)?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(CoreError::InvalidHttpTarget);
    }
    let path = if authority_end == rest.len() {
        "/".to_owned()
    } else if rest[authority_end..].starts_with('?') {
        format!("/{}", &rest[authority_end..])
    } else {
        rest[authority_end..].to_owned()
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
        routing_destination: None,
        remote_prefix: Vec::new(),
        client_prefix: Vec::new(),
        shadowsocks: Some(session),
        vmess: None,
        socks_udp: None,
        user: None,
        protocol: None,
        attributes: HashMap::new(),
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
    let socket = connect_udp_to_host(&server.address, server.port).await?;
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
    NestedTls(Box<tokio_native_tls::TlsStream<OutboundStream>>),
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
            Self::NestedTls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
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
            Self::NestedTls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::NestedTls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::NestedTls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn connect_tcp_with_source(
    destination: &Destination,
    source_ip: Option<IpAddr>,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<TcpStream, CoreError> {
    if tcp_connect_needs_preconfigured_socket(stream_settings, source_ip) {
        return timeout(
            CONNECT_TIMEOUT,
            connect_with_preconfigured_tcp_socket(destination, source_ip, stream_settings),
        )
        .await
        .map_err(|_| CoreError::Timeout)?;
    }
    timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((destination.host.to_string(), destination.port)),
    )
    .await
    .map_err(|_| CoreError::Timeout)?
    .map_err(Into::into)
}

async fn connect_with_preconfigured_tcp_socket(
    destination: &Destination,
    source_ip: Option<IpAddr>,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<TcpStream, CoreError> {
    let remotes = lookup_host((destination.host.to_string(), destination.port)).await?;
    let remotes = compatible_tcp_remotes(remotes, source_ip, stream_settings);
    if remotes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no matching address family",
        )
        .into());
    }

    let mut last_error = None;
    for remote in remotes {
        let socket = match remote {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        if let Some(source_ip) = source_ip {
            socket.bind(SocketAddr::new(source_ip, 0))?;
        }
        apply_preconnect_tcp_socket_options(&socket, stream_settings)?;
        match socket.connect(remote).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no remote addresses"))
        .into())
}

fn compatible_tcp_remotes(
    remotes: impl IntoIterator<Item = SocketAddr>,
    source_ip: Option<IpAddr>,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Vec<SocketAddr> {
    let remotes = remotes
        .into_iter()
        .filter(|addr| source_ip.is_none_or(|ip| addr.is_ipv4() == ip.is_ipv4()))
        .collect::<Vec<_>>();
    order_tcp_remotes_by_domain_strategy(remotes, tcp_sockopt_domain_strategy(stream_settings))
}

fn tcp_sockopt_domain_strategy(
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Option<&str> {
    stream_settings
        .and_then(|settings| settings.sockopt.as_ref())
        .and_then(|sockopt| sockopt.domain_strategy.as_deref())
}

fn order_tcp_remotes_by_domain_strategy(
    remotes: Vec<SocketAddr>,
    strategy: Option<&str>,
) -> Vec<SocketAddr> {
    match strategy {
        Some("UseIPv4") => remotes.into_iter().filter(SocketAddr::is_ipv4).collect(),
        Some("UseIPv6") => remotes.into_iter().filter(SocketAddr::is_ipv6).collect(),
        Some("UseIPv4v6") => ordered_tcp_remotes_by_family(remotes, true),
        Some("UseIPv6v4") => ordered_tcp_remotes_by_family(remotes, false),
        _ => remotes,
    }
}

fn ordered_tcp_remotes_by_family(remotes: Vec<SocketAddr>, ipv4_first: bool) -> Vec<SocketAddr> {
    let (preferred, fallback): (Vec<_>, Vec<_>) = remotes
        .into_iter()
        .partition(|addr| addr.is_ipv4() == ipv4_first);
    preferred.into_iter().chain(fallback).collect()
}

fn freedom_send_through_ip(outbound: &OutboundConfig) -> Option<IpAddr> {
    outbound
        .send_through
        .as_deref()
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse().ok())
}

fn freedom_udp_bind_addr(destination: &Destination, source_ip: Option<IpAddr>) -> SocketAddr {
    match source_ip {
        Some(ip) => SocketAddr::new(ip, 0),
        None => match destination.host {
            DestinationHost::Ip(IpAddr::V6(_)) => {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            }
            _ => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        },
    }
}

fn outbound_uses_tls(outbound: &OutboundConfig) -> bool {
    outbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.security.as_deref())
        == Some("tls")
}

fn apply_tcp_socket_options(
    stream: &TcpStream,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    apply_tcp_no_delay(stream, stream_settings)?;
    apply_tcp_keepalive(stream, stream_settings)?;
    apply_tcp_user_timeout(stream, stream_settings)
}

fn apply_tcp_no_delay(
    stream: &TcpStream,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    if stream_settings
        .and_then(|settings| settings.sockopt.as_ref())
        .is_some_and(|sockopt| sockopt.tcp_no_delay)
    {
        stream.set_nodelay(true)?;
    }
    Ok(())
}

fn apply_tcp_keepalive(
    stream: &TcpStream,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    let Some(sockopt) = stream_settings.and_then(|settings| settings.sockopt.as_ref()) else {
        return Ok(());
    };
    let (idle, interval) = tcp_keepalive_duration_options(sockopt);
    if idle.is_none() && interval.is_none() {
        return Ok(());
    }

    let mut keepalive = TcpKeepalive::new();
    if let Some(idle) = idle {
        keepalive = keepalive.with_time(idle);
    }
    if let Some(interval) = interval {
        keepalive = keepalive.with_interval(interval);
    }
    let socket = SockRef::from(stream);
    socket.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

fn tcp_keepalive_duration_options(
    sockopt: &xrs_config::SockoptConfig,
) -> (Option<Duration>, Option<Duration>) {
    (
        sockopt
            .tcp_keep_alive_idle
            .filter(|idle| *idle > 0)
            .map(Duration::from_secs),
        sockopt
            .tcp_keep_alive_interval
            .filter(|interval| *interval > 0)
            .map(Duration::from_secs),
    )
}

fn apply_tcp_user_timeout(
    stream: &TcpStream,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    let Some(sockopt) = stream_settings.and_then(|settings| settings.sockopt.as_ref()) else {
        return Ok(());
    };
    let Some(timeout) = tcp_user_timeout_duration_option(sockopt) else {
        return Ok(());
    };
    set_tcp_user_timeout(stream, timeout)
}

fn tcp_user_timeout_duration_option(sockopt: &xrs_config::SockoptConfig) -> Option<Duration> {
    sockopt
        .tcp_user_timeout
        .filter(|timeout| *timeout > 0)
        .map(Duration::from_millis)
}

fn tcp_fast_open_enabled(stream_settings: Option<&xrs_config::StreamSettingsConfig>) -> bool {
    stream_settings
        .and_then(|settings| settings.sockopt.as_ref())
        .is_some_and(|sockopt| sockopt.tcp_fast_open)
}

fn tcp_connect_needs_preconfigured_socket(
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
    source_ip: Option<IpAddr>,
) -> bool {
    tcp_fast_open_enabled(stream_settings)
        || source_ip.is_some()
        || tcp_sockopt_domain_strategy_needs_resolution(stream_settings)
}

fn tcp_sockopt_domain_strategy_needs_resolution(
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> bool {
    matches!(
        tcp_sockopt_domain_strategy(stream_settings),
        Some("UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4")
    )
}

fn apply_preconnect_tcp_socket_options(
    socket: &TcpSocket,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    apply_tcp_fast_open_connect(socket, stream_settings)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_tcp_fast_open_connect(
    socket: &TcpSocket,
    stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    if tcp_fast_open_enabled(stream_settings) {
        setsockopt(socket, TcpFastOpenConnect, &true).map_err(io::Error::from)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_tcp_fast_open_connect(
    _socket: &TcpSocket,
    _stream_settings: Option<&xrs_config::StreamSettingsConfig>,
) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
))]
fn set_tcp_user_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), CoreError> {
    let socket = SockRef::from(stream);
    socket.set_tcp_user_timeout(Some(timeout))?;
    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
)))]
fn set_tcp_user_timeout(_stream: &TcpStream, _timeout: Duration) -> Result<(), CoreError> {
    Ok(())
}

async fn connect_outbound_stream_with_source(
    outbound: &OutboundConfig,
    destination: &Destination,
    source_ip: Option<IpAddr>,
) -> Result<OutboundStream, CoreError> {
    let stream =
        connect_tcp_with_source(destination, source_ip, outbound.stream_settings.as_ref()).await?;
    apply_tcp_socket_options(&stream, outbound.stream_settings.as_ref())?;
    wrap_tcp_stream_tls(outbound, destination, stream).await
}

fn outbound_tls_server_name(
    outbound: &OutboundConfig,
    destination: &Destination,
) -> Result<Option<String>, CoreError> {
    if !outbound_uses_tls(outbound) {
        return Ok(None);
    }
    let tls_settings = outbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.tls_settings.as_ref());
    tls_settings
        .and_then(|settings| settings.server_name.as_deref())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| match &destination.host {
            DestinationHost::Domain(domain) => Some(domain.clone()),
            DestinationHost::Ip(_) => None,
        })
        .ok_or(CoreError::MissingTlsServerName)
        .map(Some)
}

fn outbound_tls_connector(
    outbound: &OutboundConfig,
) -> Result<tokio_native_tls::TlsConnector, CoreError> {
    let tls_settings = outbound
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.tls_settings.as_ref());
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
    Ok(tokio_native_tls::TlsConnector::from(builder.build()?))
}

async fn wrap_tcp_stream_tls(
    outbound: &OutboundConfig,
    destination: &Destination,
    stream: TcpStream,
) -> Result<OutboundStream, CoreError> {
    let Some(server_name) = outbound_tls_server_name(outbound, destination)? else {
        return Ok(OutboundStream::Tcp(stream));
    };
    let connector = outbound_tls_connector(outbound)?;
    let stream = timeout(CONNECT_TIMEOUT, connector.connect(&server_name, stream))
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(OutboundStream::Tls(stream))
}

async fn wrap_outbound_stream_tls(
    outbound: &OutboundConfig,
    destination: &Destination,
    stream: OutboundStream,
) -> Result<OutboundStream, CoreError> {
    let Some(server_name) = outbound_tls_server_name(outbound, destination)? else {
        return Ok(stream);
    };
    let connector = outbound_tls_connector(outbound)?;
    let stream = timeout(CONNECT_TIMEOUT, connector.connect(&server_name, stream))
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(OutboundStream::NestedTls(Box::new(stream)))
}

#[cfg(test)]
async fn connect_freedom(
    outbound: &OutboundConfig,
    destination: &Destination,
    source: Option<SocketAddr>,
) -> Result<OutboundStream, CoreError> {
    let destination = freedom_destination(outbound, destination).await?;
    connect_freedom_destination(outbound, &destination, source).await
}

async fn connect_freedom_for_outbound(
    outbound: &OutboundConfig,
    destination: &Destination,
    source: Option<SocketAddr>,
    outbounds: &HashMap<String, OutboundConfig>,
    dns_hosts: &DnsHosts,
) -> Result<OutboundStream, CoreError> {
    let destination = freedom_destination_with_dns_hosts(outbound, destination, dns_hosts).await?;
    let Some(proxy_tag) = outbound
        .proxy_settings
        .as_ref()
        .and_then(|settings| settings.tag.as_deref())
        .or_else(|| {
            outbound
                .stream_settings
                .as_ref()
                .and_then(|settings| settings.sockopt.as_ref())
                .and_then(|sockopt| sockopt.dialer_proxy.as_deref())
        })
        .filter(|tag| !tag.is_empty())
    else {
        return connect_freedom_destination(outbound, &destination, source).await;
    };
    let proxy = outbounds
        .get(proxy_tag)
        .ok_or_else(|| CoreError::MissingOutbound(proxy_tag.to_owned()))?;
    let mut remote =
        connect_proxy_stream_with_source(proxy, freedom_send_through_ip(outbound)).await?;
    match proxy.protocol {
        OutboundProtocol::Socks => {
            timeout(
                DEFAULT_HANDSHAKE_TIMEOUT,
                connect_socks_upstream(&mut remote, outbound_server(proxy)?, &destination),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
        }
        OutboundProtocol::Http => {
            timeout(
                DEFAULT_HANDSHAKE_TIMEOUT,
                connect_http_upstream(&mut remote, outbound_server(proxy)?, &destination),
            )
            .await
            .map_err(|_| CoreError::Timeout)??;
        }
        _ => return Err(CoreError::MissingOutbound(proxy_tag.to_owned())),
    }
    let proxy_protocol_destination = match &destination.host {
        DestinationHost::Ip(ip) => Some(SocketAddr::new(*ip, destination.port)),
        DestinationHost::Domain(_) => None,
    };
    write_freedom_proxy_protocol_header(outbound, &mut remote, source, proxy_protocol_destination)
        .await?;
    wrap_outbound_stream_tls(outbound, &destination, remote).await
}

async fn connect_freedom_destination(
    outbound: &OutboundConfig,
    destination: &Destination,
    source: Option<SocketAddr>,
) -> Result<OutboundStream, CoreError> {
    let _ = outbound_tls_server_name(outbound, destination)?;
    let mut stream = connect_tcp_with_source(
        destination,
        freedom_send_through_ip(outbound),
        outbound.stream_settings.as_ref(),
    )
    .await?;
    apply_tcp_socket_options(&stream, outbound.stream_settings.as_ref())?;
    let remote_addr = stream.peer_addr()?;
    write_freedom_proxy_protocol_header(outbound, &mut stream, source, Some(remote_addr)).await?;
    wrap_tcp_stream_tls(outbound, destination, stream).await
}

async fn write_freedom_proxy_protocol_header<S>(
    outbound: &OutboundConfig,
    stream: &mut S,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    let Some(version) = outbound
        .settings
        .as_ref()
        .and_then(|settings| settings.proxy_protocol)
        .filter(|version| *version != 0)
    else {
        return Ok(());
    };
    let source = source.ok_or(CoreError::MissingProxyProtocolSource)?;
    let header = match (version, destination) {
        (1, Some(destination)) => proxy_protocol_v1_header(source, destination),
        (1, None) => b"PROXY UNKNOWN\r\n".to_vec(),
        (2, Some(destination)) => proxy_protocol_v2_header(source, destination),
        (2, None) => proxy_protocol_v2_unknown_header(),
        _ => Vec::new(),
    };
    stream.write_all(&header).await?;
    Ok(())
}

fn proxy_protocol_v1_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let family = match (source, destination) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
        (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
        _ => "UNKNOWN",
    };
    if family == "UNKNOWN" {
        return b"PROXY UNKNOWN\r\n".to_vec();
    }
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        source.ip(),
        destination.ip(),
        source.port(),
        destination.port()
    )
    .into_bytes()
}

fn proxy_protocol_v2_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            header.extend_from_slice(&source.ip().octets());
            header.extend_from_slice(&destination.ip().octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            header.extend_from_slice(&source.ip().octets());
            header.extend_from_slice(&destination.ip().octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        _ => header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]),
    }
    header
}

fn proxy_protocol_v2_unknown_header() -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
    header
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
    async fn accepts_vmess_client_email_user() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let destination = Destination::tcp(DestinationHost::parse("example.com").unwrap(), 443);
        let (header, _session) =
            build_vmess_request(&Uuid::parse_str(id).unwrap(), &destination).unwrap();
        let mut inbound = vmess_inbound(id);
        inbound.settings.as_mut().unwrap().clients[0].email = Some("alice@example.com".to_owned());
        let replay_cache = VmessReplayCache::default();
        let mut stream = &header[..];

        let accepted = accept_vmess(&mut stream, &inbound, &replay_cache)
            .await
            .unwrap();

        assert_eq!(accepted.user.as_deref(), Some("alice@example.com"));
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
    async fn vmess_udp_command_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_vmess_proxy(id).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let (header, mut session) =
            build_vmess_udp_request(&Uuid::parse_str(id).unwrap(), &destination).unwrap();
        client.write_all(&header).await.unwrap();
        read_vmess_response_header(&mut client, &session)
            .await
            .unwrap();
        session
            .writer
            .write_chunk(&mut client, b"ping")
            .await
            .unwrap();
        let payload = session
            .reader
            .read_chunk(&mut client)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn vmess_udp_quic_sniffing_protocol_routes_quic_packets() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let mut inbound = vmess_inbound(id);
        inbound.sniffing = Some(sniffing_config("quic"));
        let mut protocol_rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        protocol_rule.protocol = vec!["quic".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let (header, mut session) =
            build_vmess_udp_request(&Uuid::parse_str(id).unwrap(), &destination).unwrap();
        client.write_all(&header).await.unwrap();
        read_vmess_response_header(&mut client, &session)
            .await
            .unwrap();
        session
            .writer
            .write_chunk(&mut client, quic_initial_packet())
            .await
            .unwrap();

        assert!(
            timeout(
                Duration::from_millis(100),
                session.reader.read_chunk(&mut client)
            )
            .await
            .is_err()
        );
        assert!(!upstream_task.is_finished());
        upstream_task.abort();
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
    async fn socks5_inbound_reaches_echo_server_through_aes_gcm_vmess_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vmess_upstream(echo_port, id).await;
        let outbound = vmess_outbound_with_security("upstream", upstream_port, id, "aes-128-gcm");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vmag")
            .await;
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_auto_vmess_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vmess_upstream(echo_port, id).await;
        let outbound = vmess_outbound_with_security("upstream", upstream_port, id, "auto");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vmat")
            .await;
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_chacha20_vmess_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vmess_upstream(echo_port, id).await;
        let outbound =
            vmess_outbound_with_security("upstream", upstream_port, id, "chacha20-poly1305");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vmch")
            .await;
    }

    #[test]
    fn vmess_omitted_security_uses_xray_auto_default() {
        let mut outbound =
            vmess_outbound("upstream", 10086, "01234567-89ab-cdef-0123-456789abcdef");
        let server = outbound
            .settings
            .as_mut()
            .unwrap()
            .servers
            .first_mut()
            .unwrap();
        server.security = None;

        assert_eq!(
            vmess_server_security(server).unwrap(),
            VmessBodySecurity::Aes128Gcm
        );
    }

    #[tokio::test]
    async fn vmess_aes_gcm_framing_ends_with_authenticated_empty_chunk() {
        let mut writer = VmessWriter {
            key: [3_u8; 16],
            iv: [7_u8; 16],
            nonce: 0,
            masked: true,
            security: VmessBodySecurity::Aes128Gcm,
        };
        let (mut client, mut server) = duplex(128);

        writer.write_end(&mut client).await.unwrap();
        let mut frame = [0_u8; 32];
        let length = server.read(&mut frame).await.unwrap();
        let mut encoded_len = [frame[0], frame[1]];
        vmess_mask_length(&mut encoded_len, &[7_u8; 16], 0);

        assert_eq!(u16::from_be_bytes(encoded_len), 16);
        assert_eq!(length, 18);
    }

    #[test]
    fn vmess_chacha20_security_uses_xray_wire_values() {
        let key = [1_u8; 16];
        let expected_key = [
            0x24, 0x31, 0x1d, 0x9a, 0xbc, 0x40, 0x77, 0x12, 0x3c, 0x2c, 0x9a, 0x16, 0x7a, 0xfb,
            0xe7, 0x54, 0xe6, 0xa5, 0x58, 0x15, 0xcf, 0xef, 0xf7, 0xa4, 0xd7, 0x3f, 0x9a, 0x77,
            0xbf, 0xf8, 0xdf, 0x74,
        ];

        assert_eq!(VMESS_SECURITY_CHACHA20_POLY1305, 4);
        assert_eq!(vmess_chacha20_key(&key), expected_key);
        assert_eq!(
            vmess_body_nonce(&[7_u8; 16], 1),
            [0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]
        );
    }

    #[tokio::test]
    async fn vmess_aead_writer_rejects_nonce_reuse_boundary() {
        let mut writer = VmessWriter {
            key: [3_u8; 16],
            iv: [7_u8; 16],
            nonce: u16::MAX as u32 + 1,
            masked: true,
            security: VmessBodySecurity::Chacha20Poly1305,
        };
        let (mut client, _server) = duplex(128);

        assert!(matches!(
            writer.write_chunk(&mut client, b"overflow").await,
            Err(CoreError::MalformedVmessRequest)
        ));
    }

    #[tokio::test]
    async fn vmess_aead_reader_rejects_nonce_reuse_boundary() {
        let mut reader = VmessReader {
            key: [3_u8; 16],
            iv: [7_u8; 16],
            nonce: u16::MAX as u32 + 1,
            masked: true,
            security: VmessBodySecurity::Chacha20Poly1305,
        };
        let (_client, mut server) = duplex(128);

        assert!(matches!(
            reader.read_chunk(&mut server).await,
            Err(CoreError::MalformedVmessRequest)
        ));
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_vless_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vless_upstream(echo_port, id).await;
        let outbound = vless_outbound("upstream", upstream_port, id);
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"vlou")
            .await;
    }

    #[tokio::test]
    async fn vmess_inbound_reaches_echo_server_through_vless_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vless_upstream(echo_port, id).await;
        let (proxy_port, proxy_task) = start_proxy_with_outbound(
            vmess_inbound(id),
            vless_outbound("upstream", upstream_port, id),
        )
        .await;
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
            .write_chunk(&mut client, b"vmvl")
            .await
            .unwrap();
        let echoed = session
            .reader
            .read_chunk(&mut client)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"vmvl");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn shadowsocks_inbound_reaches_echo_server_through_vless_upstream() {
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let upstream_port = start_vless_upstream(echo_port, id).await;
        let (proxy_port, proxy_task) = start_proxy_with_outbound(
            shadowsocks_inbound("secret"),
            vless_outbound("upstream", upstream_port, id),
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut session = start_shadowsocks_client(&mut client, "secret").await;
        let mut payload = encode_shadowsocks_address(&Destination::tcp(
            DestinationHost::parse("127.0.0.1").unwrap(),
            echo_port,
        ))
        .unwrap();
        payload.extend_from_slice(b"ssvl");
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
        assert_eq!(&echoed, b"ssvl");
        proxy_task.abort();
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
                extra: Default::default(),
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
    async fn socks5_inbound_reaches_echo_server_through_chained_freedom_socks_proxy() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_socks_upstream(echo_port).await;
        let mut direct = freedom_outbound_with_domain_strategy(None);
        direct.proxy_settings = Some(xrs_config::ProxySettingsConfig {
            tag: Some("proxy".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        let proxy = socks_outbound("proxy", upstream_port, None, None);
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![direct, proxy],
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

        client.write_all(b"chns").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"chns");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_tls_echo_through_chained_freedom_socks_proxy() {
        let echo_port = start_tls_echo_server().await;
        let upstream_port = start_socks_upstream(echo_port).await;
        let mut direct = freedom_outbound_with_domain_strategy(None);
        direct.proxy_settings = Some(xrs_config::ProxySettingsConfig {
            tag: Some("proxy".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        direct.stream_settings = Some(tls_stream_settings());
        let proxy = socks_outbound("proxy", upstream_port, None, None);
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![direct, proxy],
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

        client.write_all(b"chtl").await.unwrap();
        let mut echoed = [0_u8; 4];
        timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"chtl");
        proxy_task.abort();
    }

    #[test]
    fn parse_dns_hosts_uses_first_ip_from_array_values() {
        let hosts = parse_dns_hosts(Some(&serde_json::json!({
            "hosts": {"Mapped.Test.": ["203.0.113.7", "2001:db8::1"]}
        })));

        assert_eq!(
            hosts.get("mapped.test"),
            Some(&IpAddr::V4("203.0.113.7".parse().unwrap()))
        );
    }

    #[test]
    fn parse_dns_hosts_honors_query_strategy_for_array_values() {
        let hosts = parse_dns_hosts(Some(&serde_json::json!({
            "queryStrategy": "UseIPv6",
            "hosts": {"Mapped.Test.": ["203.0.113.7", "2001:db8::1"]}
        })));

        assert_eq!(
            hosts.get("mapped.test"),
            Some(&IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn parse_dns_hosts_resolves_string_alias_values() {
        let hosts = parse_dns_hosts(Some(&serde_json::json!({
            "hosts": {
                "Alias.Test": "Target.Test.",
                "target.test": "198.51.100.9"
            }
        })));

        assert_eq!(
            hosts.get("alias.test"),
            Some(&IpAddr::V4("198.51.100.9".parse().unwrap()))
        );
    }

    #[test]
    fn parse_dns_hosts_accepts_domain_prefixed_keys() {
        let hosts = parse_dns_hosts(Some(&serde_json::json!({
            "hosts": {"domain:Mapped.Test.": "192.0.2.44"}
        })));

        assert_eq!(
            hosts.get("mapped.test"),
            Some(&IpAddr::V4("192.0.2.44".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn domain_prefixed_dns_hosts_match_subdomains() {
        let outbound = freedom_outbound_with_tag("direct");
        let destination =
            Destination::tcp(DestinationHost::Domain("api.mapped.test".to_owned()), 443);
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "hosts": {"domain:mapped.test": "192.0.2.44"}
        }))));

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("192.0.2.44".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn dns_hosts_normalize_query_domain_case_and_trailing_dot() {
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(DestinationHost::Domain("Mapped.Test.".to_owned()), 443);
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "hosts": {"mapped.test": "192.0.2.46"}
        }))));

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("192.0.2.46".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn keyword_prefixed_dns_hosts_match_containing_domains() {
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api.ads-cdn.example".to_owned()),
            443,
        );
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "hosts": {"keyword:ads": "192.0.2.47"}
        }))));

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("192.0.2.47".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn regexp_prefixed_dns_hosts_match_domains() {
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api-42.mapped.test".to_owned()),
            443,
        );
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "hosts": {r"regexp:^api-[0-9]+\.mapped\.test$": "192.0.2.48"}
        }))));

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("192.0.2.48".parse().unwrap())
        );
    }

    #[test]
    fn parse_dns_hosts_accepts_full_prefixed_keys() {
        let hosts = parse_dns_hosts(Some(&serde_json::json!({
            "hosts": {"full:Exact.Test.": "192.0.2.45"}
        })));

        assert_eq!(
            hosts.get("exact.test"),
            Some(&IpAddr::V4("192.0.2.45".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn top_level_dns_hosts_resolve_freedom_domain_targets() {
        let echo_port = start_echo_server().await;
        let (proxy_port, proxy_task) = start_proxy_with_dns(
            serde_json::json!({"hosts":{"example.test":"127.0.0.1"}}),
            test_inbound(InboundProtocol::Socks),
            vec![freedom_outbound_with_tag("direct")],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "example.test", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(b"dns!").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"dns!");
        proxy_task.abort();
    }

    #[test]
    fn parse_runtime_dns_accepts_string_form_servers() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "servers": ["127.0.0.1"]
        })));

        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].address, "127.0.0.1");
        assert_eq!(dns.servers[0].port, 53);
        assert!(!dns.servers[0].skip_fallback);
    }

    #[test]
    fn parse_runtime_dns_rejects_blank_string_form_servers() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "servers": ["", "   "]
        })));

        assert!(dns.servers.is_empty());
    }

    #[test]
    fn parse_runtime_dns_accepts_server_client_ip_casing() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "clientIp":"192.0.2.7",
            "servers": [{"address":"127.0.0.1","clientIp":"198.51.100.9"}]
        })));

        assert_eq!(
            dns.servers[0].client_ip,
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn parse_runtime_dns_accepts_top_level_client_ip_casing() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "clientIP":"192.0.2.7",
            "servers": ["127.0.0.1"]
        })));

        assert_eq!(dns.servers[0].client_ip, Some("192.0.2.7".parse().unwrap()));
    }

    #[test]
    fn parse_runtime_dns_rejects_unsupported_server_uri_schemes() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "servers": ["https://dns.google/dns-query", {"address":"tls://1.1.1.1"}]
        })));

        assert!(dns.servers.is_empty());
    }

    #[test]
    fn parse_runtime_dns_rejects_zero_uri_ports() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "servers": ["tcp://1.1.1.1:0", {"address":"udp://1.1.1.1:0"}]
        })));

        assert!(dns.servers.is_empty());
    }

    #[test]
    fn parse_runtime_dns_rejects_malformed_uri_ports() {
        let dns = parse_runtime_dns(Some(&serde_json::json!({
            "servers": [
                "tcp://1.1.1.1:65536",
                "tcp://1.1.1.1:notaport",
                {"address":"udp://1.1.1.1:"}
            ]
        })));

        assert!(dns.servers.is_empty());
    }

    #[tokio::test]
    async fn string_form_tcp_dns_servers_resolve_freedom_domain_targets() {
        let (dns_port, dns_task) = start_tcp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [format!("tcp://127.0.0.1:{dns_port}")]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
    }

    #[tokio::test]
    async fn object_form_tcp_dns_servers_resolve_freedom_domain_targets() {
        let (dns_port, dns_task) = start_tcp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [{"address": format!("tcp://127.0.0.1:{dns_port}")}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
    }

    #[tokio::test]
    async fn tcp_dns_servers_reject_zero_length_responses() {
        let (dns_port, _dns_task) = start_length_only_tcp_dns_server(0).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [format!("tcp://127.0.0.1:{dns_port}")]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let error = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::InvalidDnsMessageLength));
    }

    #[tokio::test]
    async fn tcp_dns_servers_reject_oversized_responses() {
        let (dns_port, _dns_task) = start_oversized_tcp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [format!("tcp://127.0.0.1:{dns_port}")]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let error = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::DnsMessageTooLarge));
    }

    #[tokio::test]
    async fn string_form_udp_dns_servers_resolve_freedom_domain_targets() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [format!("udp://127.0.0.1:{dns_port}")]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
    }

    #[tokio::test]
    async fn object_form_udp_dns_servers_resolve_freedom_domain_targets() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [{"address": format!("udp://127.0.0.1:{dns_port}")}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
    }

    #[tokio::test]
    async fn top_level_dns_client_ip_adds_ecs_metadata_to_queries() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "clientIp":"192.0.2.7",
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(query.windows(12).any(|window| {
            window == [0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x20, 0x00, 192, 0, 2, 7]
        }));
    }

    #[tokio::test]
    async fn dns_server_client_ip_overrides_top_level_client_ip() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "clientIp":"192.0.2.7",
            "servers": [{"address":"127.0.0.1","port":dns_port,"clientIP":"198.51.100.9"}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(query.windows(12).any(|window| {
            window
                == [
                    0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x20, 0x00, 198, 51, 100, 9,
                ]
        }));
    }

    #[tokio::test]
    async fn empty_dns_server_client_ip_disables_top_level_client_ip() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "clientIp":"192.0.2.7",
            "servers": [{"address":"127.0.0.1","port":dns_port,"clientIP":""}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(!query.windows(12).any(|window| {
            window == [0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x20, 0x00, 192, 0, 2, 7]
        }));
    }

    #[tokio::test]
    async fn top_level_dns_servers_resolve_freedom_domain_targets() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
    }

    #[test]
    fn dns_response_rejects_mismatched_transaction_id() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 9]));
        response[0] = 0xab;
        response[1] = 0xcd;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_truncated_answers() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 10]));
        response[2] |= 0x02;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_non_response_messages() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 11]));
        response[2] &= 0x7f;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_non_query_opcodes() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 12]));
        response[2] |= 0x08;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_wrong_question_count() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 13]));
        let question_end = skip_dns_name(&response, 12).unwrap() + 4;
        let question = response[12..question_end].to_vec();
        response.splice(question_end..question_end, question);
        response[4] = 0;
        response[5] = 2;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_wrong_question_type() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 14]));
        let question_offset = skip_dns_name(&response, 12).unwrap();
        response[question_offset] = 0;
        response[question_offset + 1] = 28;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_wrong_question_class() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 15]));
        let question_offset = skip_dns_name(&response, 12).unwrap();
        response[question_offset + 2] = 0;
        response[question_offset + 3] = 3;

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_rejects_unrelated_answer_owner() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&query, 1, IpAddr::from([203, 0, 113, 16]));
        let question_end = skip_dns_name(&response, 12).unwrap() + 4;
        response.splice(
            question_end..question_end + 2,
            [
                5, b'o', b't', b'h', b'e', b'r', 4, b't', b'e', b's', b't', 0,
            ],
        );

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[test]
    fn dns_response_accepts_cname_answer_chain() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let response = dns_cname_response_for_query(&query, IpAddr::from([127, 0, 0, 1]));

        assert_eq!(
            parse_dns_response(&response, &query, 1),
            Some(IpAddr::from([127, 0, 0, 1]))
        );
    }

    #[test]
    fn dns_response_rejects_rewritten_question_and_answer_owner() {
        let query = build_dns_query("configured-dns.test", 1, None).unwrap();
        let other_query = build_dns_query("other.test", 1, None).unwrap();
        let mut response = dns_response_for_query(&other_query, 1, IpAddr::from([203, 0, 113, 17]));
        response[0] = query[0];
        response[1] = query[1];

        assert_eq!(parse_dns_response(&response, &query, 1), None);
    }

    #[tokio::test]
    async fn dns_servers_honor_use_ipv6_query_strategy() {
        let expected_ip = "2001:db8::1".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_aaaa_server(expected_ip).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "queryStrategy": "UseIPv6",
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::Ip(expected_ip));
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        let question_end = skip_dns_name(&query, 12).unwrap();
        assert_eq!(
            &query[question_end..question_end + 2],
            &28_u16.to_be_bytes()
        );
    }

    #[tokio::test]
    async fn dns_servers_honor_use_ipv4v6_query_strategy_fallback() {
        let expected_ip = "2001:db8::2".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_fallback_server(28, expected_ip).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "queryStrategy": "UseIPv4v6",
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::Ip(expected_ip));
        let queries = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dns_question_record_type(&queries[0]), 1);
        assert_eq!(dns_question_record_type(&queries[1]), 28);
    }

    #[tokio::test]
    async fn dns_servers_honor_use_ip_query_strategy_fallback() {
        let expected_ip = "2001:db8::4".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_fallback_server(28, expected_ip).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "queryStrategy": "UseIP",
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::Ip(expected_ip));
        let queries = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dns_question_record_type(&queries[0]), 1);
        assert_eq!(dns_question_record_type(&queries[1]), 28);
    }

    #[tokio::test]
    async fn dns_servers_honor_use_ipv6v4_query_strategy_fallback() {
        let expected_ip = "127.0.0.9".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_fallback_server(1, expected_ip).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "queryStrategy": "UseIPv6v4",
            "servers": [{"address":"127.0.0.1","port":dns_port}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::Ip(expected_ip));
        let queries = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dns_question_record_type(&queries[0]), 28);
        assert_eq!(dns_question_record_type(&queries[1]), 1);
    }

    #[tokio::test]
    async fn dns_server_query_strategy_overrides_top_level_strategy() {
        let expected_ip = "2001:db8::3".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_aaaa_server(expected_ip).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [{"address":"127.0.0.1","port":dns_port,"queryStrategy":"UseIPv6"}]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::Ip(expected_ip));
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dns_question_record_type(&query), 28);
    }

    #[test]
    fn dns_server_domain_filters_normalize_requested_domains() {
        let server = RuntimeDnsServer {
            address: "127.0.0.1".to_owned(),
            port: 53,
            transport: RuntimeDnsTransport::Udp,
            domains: vec!["domain:configured-dns.test".to_owned()],
            expect_ips: Vec::new(),
            client_ip: None,
            query_strategy: None,
            skip_fallback: false,
        };

        assert!(dns_server_matches_domain(
            &server,
            "API.CONFIGURED-DNS.TEST."
        ));
    }

    #[tokio::test]
    async fn dns_server_domain_filters_choose_matching_server() {
        let (other_port, other_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let (matched_port, matched_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [
                {"address":"127.0.0.1","port":other_port,"domains":["domain:other.test"]},
                {"address":"127.0.0.1","port":matched_port,"domains":["domain:configured-dns.test"]}
            ]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api.configured-dns.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        let query = timeout(Duration::from_millis(200), matched_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            query
                .windows(b"configured-dns".len())
                .any(|window| window == b"configured-dns")
        );
        other_task.abort();
    }

    #[tokio::test]
    async fn dns_server_expected_ips_reject_non_matching_answers() {
        let (wrong_port, wrong_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let (matched_port, matched_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [
                {"address":"127.0.0.1","port":wrong_port,"expectIPs":["127.0.0.1"]},
                {"address":"127.0.0.1","port":matched_port,"expectIPs":["127.0.0.1"]}
            ]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination =
            Destination::tcp(DestinationHost::Domain("expected-ip.test".to_owned()), 443);

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        timeout(Duration::from_millis(200), wrong_task)
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_millis(200), matched_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn disable_fallback_stops_system_resolution_after_configured_dns_miss() {
        let (wrong_port, wrong_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "disableFallback": true,
            "servers": [{"address":"127.0.0.1","port":wrong_port,"domains":["domain:localhost"],"expectIPs":["127.0.0.1"]}]
        }))));
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        let destination = Destination::tcp(DestinationHost::Domain("localhost".to_owned()), 443);

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Domain("localhost".to_owned())
        );
        timeout(Duration::from_millis(200), wrong_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn freedom_redirect_applies_when_configured_dns_suppresses_fallback() {
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "disableFallback": true,
            "servers": [{"address":"127.0.0.1","port":9,"domains":["domain:localhost"],"expectIPs":["127.0.0.1"]}]
        }))));
        let mut outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        outbound.settings.as_mut().unwrap().redirect = Some("127.0.0.1:8443".to_owned());
        let destination = Destination::tcp(DestinationHost::Domain("localhost".to_owned()), 443);

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(resolved.host, DestinationHost::parse("127.0.0.1").unwrap());
        assert_eq!(resolved.port, 8443);
        assert_eq!(resolved.network, Network::Tcp);
    }

    #[tokio::test]
    async fn disable_fallback_if_match_stops_after_filtered_dns_server_rejects_answer() {
        let (wrong_port, wrong_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let (fallback_port, fallback_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "disableFallbackIfMatch": true,
            "servers": [
                {"address":"127.0.0.1","port":wrong_port,"domains":["domain:expected-ip.test"],"expectIPs":["127.0.0.1"]},
                {"address":"127.0.0.1","port":fallback_port,"expectIPs":["127.0.0.1"]}
            ]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api.expected-ip.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Domain("api.expected-ip.test".to_owned())
        );
        timeout(Duration::from_millis(200), wrong_task)
            .await
            .unwrap()
            .unwrap();
        fallback_task.abort();
    }

    #[tokio::test]
    async fn dns_server_skip_fallback_matching_server_still_allows_later_fallback() {
        let (wrong_port, wrong_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let (fallback_port, fallback_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [
                {"address":"127.0.0.1","port":wrong_port,"domains":["domain:expected-ip.test"],"expectIPs":["127.0.0.1"],"skipFallback":true},
                {"address":"127.0.0.1","port":fallback_port,"expectIPs":["127.0.0.1"]}
            ]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api.expected-ip.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        timeout(Duration::from_millis(200), wrong_task)
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_millis(200), fallback_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dns_server_skip_fallback_non_matching_server_is_not_used_as_fallback() {
        let (skipped_port, skipped_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let (fallback_port, fallback_task) = start_udp_dns_a_server([127, 0, 0, 1]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "servers": [
                {"address":"127.0.0.1","port":skipped_port,"domains":["domain:other.test"],"skipFallback":true},
                {"address":"127.0.0.1","port":fallback_port}
            ]
        }))));
        let outbound = freedom_outbound_with_tag("direct");
        let destination = Destination::tcp(
            DestinationHost::Domain("api.expected-ip.test".to_owned()),
            443,
        );

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip("127.0.0.1".parse().unwrap())
        );
        timeout(Duration::from_millis(200), fallback_task)
            .await
            .unwrap()
            .unwrap();
        skipped_task.abort();
    }

    #[tokio::test]
    async fn disable_fallback_if_match_stops_freedom_system_resolution_after_filtered_miss() {
        let (wrong_port, wrong_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let dns_hosts = Arc::new(parse_runtime_dns(Some(&serde_json::json!({
            "disableFallbackIfMatch": true,
            "servers": [{"address":"127.0.0.1","port":wrong_port,"domains":["domain:localhost"],"expectIPs":["127.0.0.1"]}]
        }))));
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        let destination = Destination::tcp(DestinationHost::Domain("localhost".to_owned()), 443);

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Domain("localhost".to_owned())
        );
        timeout(Duration::from_millis(200), wrong_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_freedom_dialer_proxy() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_socks_upstream(echo_port).await;
        let mut direct = freedom_outbound_with_domain_strategy(None);
        direct.stream_settings = Some(xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                dialer_proxy: Some("proxy".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        });
        let proxy = socks_outbound("proxy", upstream_port, None, None);
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![direct, proxy],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "198.51.100.7", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(b"dpro").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"dpro");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn freedom_proxy_settings_send_through_applies_to_proxy_connection() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_socks_upstream(echo_port).await;
        let mut direct = freedom_outbound_with_domain_strategy(None);
        direct.send_through = Some("192.0.2.1".to_owned());
        direct.proxy_settings = Some(xrs_config::ProxySettingsConfig {
            tag: Some("proxy".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        let proxy = socks_outbound("proxy", upstream_port, None, None);
        let dns_hosts = Arc::new(RuntimeDns::default());
        let result = connect_freedom_for_outbound(
            &direct,
            &Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), echo_port),
            None,
            &HashMap::from([("proxy".to_owned(), proxy)]),
            &dns_hosts,
        )
        .await;

        assert!(matches!(
            result,
            Err(CoreError::Io(_)) | Err(CoreError::Timeout)
        ));
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
            extra: Default::default(),
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
        assert_eq!(accepted.user.as_deref(), Some("user"));
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
    async fn rejects_socks5_udp_associate_when_udp_is_disabled() {
        for udp in [None, Some(false)] {
            let (mut client, mut server) = duplex(1024);
            let mut inbound = test_inbound(InboundProtocol::Socks);
            inbound.settings = Some(xrs_config::InboundSettings {
                udp,
                ..xrs_config::InboundSettings::default()
            });
            let task = tokio::spawn(async move { accept_socks5(&mut server, &inbound).await });

            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method = [0_u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, 0x00]);
            client
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            assert!(matches!(
                task.await.unwrap(),
                Err(CoreError::UnsupportedSocksCommand(0x03))
            ));
        }
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy(Vec::new()).await;
        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_drops_udp_through_blackhole() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", 53);
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy(vec![rule]).await;
        let (_tcp, udp, udp_relay) = start_socks_udp_associate(proxy_port).await;

        let blocked_destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };
        let blocked_packet = encode_socks_udp_packet(&blocked_destination, b"blocked").unwrap();
        udp.send_to(&blocked_packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let mut buffer = [0_u8; 128];
        assert!(
            timeout(Duration::from_millis(100), udp.recv(&mut buffer))
                .await
                .is_err()
        );

        let allowed_destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let allowed_packet = encode_socks_udp_packet(&allowed_destination, b"ping").unwrap();
        udp.send_to(&allowed_packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination, allowed_destination);
        assert_eq!(parsed.payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_quic_sniffing_protocol_routes_quic_packets() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let mut inbound = socks_udp_inbound();
        inbound.sniffing = Some(sniffing_config("quic"));
        let mut protocol_rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        protocol_rule.protocol = vec!["quic".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let (_tcp, udp, udp_relay) = start_socks_udp_associate(proxy_port).await;
        let packet = encode_socks_udp_packet(&destination, quic_initial_packet()).unwrap();
        udp.send_to(&packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let mut buffer = [0_u8; 128];

        assert!(
            timeout(Duration::from_millis(100), udp.recv(&mut buffer))
                .await
                .is_err()
        );
        assert!(!upstream_task.is_finished());
        proxy_task.abort();
        upstream_task.abort();
    }

    #[test]
    fn quic_sniffing_ignores_non_initial_long_header_packets() {
        let mut packet = quic_initial_packet().to_vec();
        packet[0] = 0xe0;

        assert!(!is_quic_initial_packet(&packet));
    }

    #[test]
    fn quic_sniffing_rejects_structurally_incomplete_initial_packets() {
        assert!(!is_quic_initial_packet(&[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ]));
    }

    #[test]
    fn quic_sniffing_rejects_truncated_source_connection_id() {
        assert!(!is_quic_initial_packet(&[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x04, 0xbb,
        ]));
    }

    #[test]
    fn quic_sniffing_rejects_declared_packet_length_past_payload() {
        let mut packet = quic_initial_packet().to_vec();
        let packet_len_offset = packet.len() - 3;
        packet[packet_len_offset] = 0x08;
        packet.truncate(packet_len_offset + 1);

        assert!(!is_quic_initial_packet(&packet));
    }

    #[tokio::test]
    async fn socks5_udp_associate_drops_malformed_packet_without_stopping() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy(Vec::new()).await;
        let (_tcp, udp, udp_relay) = start_socks_udp_associate(proxy_port).await;

        let malformed_packet = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53, b'x'];
        udp.send_to(&malformed_packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let mut buffer = [0_u8; 128];
        assert!(
            timeout(Duration::from_millis(100), udp.recv(&mut buffer))
                .await
                .is_err()
        );

        let allowed_destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let allowed_packet = encode_socks_udp_packet(&allowed_destination, b"ping").unwrap();
        udp.send_to(&allowed_packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination, allowed_destination);
        assert_eq!(parsed.payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_on_ipv6_inbound_returns_ipv6_relay() {
        let (upstream_port, upstream_task) = start_udp_dns_server_on("::1", b"pong".to_vec()).await;
        let mut inbound = socks_udp_inbound();
        inbound.listen = Some("::1".parse().unwrap());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            Vec::new(),
            vec![freedom_outbound_with_domain_strategy(None)],
        )
        .await;

        let (_tcp, udp, udp_relay) = start_socks_udp_associate_on("::1", proxy_port).await;
        assert!(udp_relay.ip().is_ipv6());
        let destination = Destination {
            host: DestinationHost::parse("::1").unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let packet = encode_socks_udp_packet(&destination, b"ping").unwrap();
        udp.send_to(&packet, udp_relay).await.unwrap();
        let mut buffer = [0_u8; 128];
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_ip_on_demand_preserves_ip_rule_priority_over_domain_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let ip_rule = udp_route_rule(
            Vec::new(),
            vec!["127.0.0.1", "::1"],
            "blocked",
            upstream_port,
        );
        let domain_rule = udp_route_rule(vec!["localhost"], Vec::new(), "direct", upstream_port);
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy_with_domain_strategy(
            Some("IPOnDemand".to_owned()),
            vec![ip_rule, domain_rule],
        )
        .await;

        assert_socks_udp_no_response(proxy_port, "localhost", upstream_port).await;
        assert!(!upstream_task.is_finished());
        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_use_ipv4_ignores_ipv6_only_ip_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), vec!["::1"], "blocked", upstream_port);
        let (proxy_port, proxy_task) =
            start_socks_udp_test_proxy_with_domain_strategy(Some("UseIPv4".to_owned()), vec![rule])
                .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "localhost", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_use_ipv6_applies_ipv6_ip_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), vec!["::1"], "blocked", upstream_port);
        let (proxy_port, proxy_task) =
            start_socks_udp_test_proxy_with_domain_strategy(Some("UseIPv6".to_owned()), vec![rule])
                .await;

        assert_socks_udp_no_response(proxy_port, "localhost", upstream_port).await;
        assert!(!upstream_task.is_finished());
        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_use_ipv4v6_falls_back_to_ipv6_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), vec!["::1"], "direct", upstream_port);
        let (proxy_port, proxy_task) = start_proxy_with_domain_strategy_and_outbounds(
            socks_udp_inbound(),
            Some("UseIPv4v6".to_owned()),
            vec![rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "localhost", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_use_ipv6v4_falls_back_to_ipv4_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), vec!["127.0.0.1"], "direct", upstream_port);
        let (proxy_port, proxy_task) = start_proxy_with_domain_strategy_and_outbounds(
            socks_udp_inbound(),
            Some("UseIPv6v4".to_owned()),
            vec![rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "localhost", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_dual_family_strategy_ignores_non_ip_rules_when_resolved() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy_with_domain_strategy(
            Some("UseIPv4v6".to_owned()),
            vec![rule],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "localhost", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_ip_if_non_match_resolves_domain_for_ip_rules() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(
            Vec::new(),
            vec!["127.0.0.1", "::1"],
            "blocked",
            upstream_port,
        );
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy_with_domain_strategy(
            Some("IPIfNonMatch".to_owned()),
            vec![rule],
        )
        .await;

        assert_socks_udp_no_response(proxy_port, "localhost", upstream_port).await;
        assert!(!upstream_task.is_finished());
        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_ip_if_non_match_keeps_domain_rule_priority() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let ip_rule = udp_route_rule(
            Vec::new(),
            vec!["127.0.0.1", "::1"],
            "blocked",
            upstream_port,
        );
        let domain_rule = udp_route_rule(vec!["localhost"], Vec::new(), "direct", upstream_port);
        let (proxy_port, proxy_task) = start_socks_udp_test_proxy_with_domain_strategy(
            Some("IPIfNonMatch".to_owned()),
            vec![ip_rule, domain_rule],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "localhost", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_rejects_tls_freedom_outbound() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
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
            extra: Default::default(),
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
    async fn freedom_send_through_binds_udp_source() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(b"pong", peer).await.unwrap();
            (buffer[..length].to_vec(), peer.ip())
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: Some("127.0.0.1".to_owned()),
            proxy_settings: None,
            settings: None,
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port,
            network: Network::Udp,
        };

        let response = send_socks_udp_payload(&outbound, &destination, b"ping")
            .await
            .unwrap();
        assert_eq!(response.payload, b"pong");
        let (payload, source_ip) = server.await.unwrap();
        assert_eq!(payload, b"ping");
        assert_eq!(source_ip, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_shadowsocks() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let shadowsocks_port = start_shadowsocks_udp_upstream("secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![shadowsocks_outbound("direct", shadowsocks_port, "secret")],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_ipv6_udp_server_through_shadowsocks() {
        let (upstream_port, upstream_task) = start_udp_dns_server_on("::1", b"pong".to_vec()).await;
        let shadowsocks_port = start_shadowsocks_udp_upstream_on("::1", "secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![shadowsocks_outbound_with_address(
                "direct",
                "::1",
                shadowsocks_port,
                "secret",
            )],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "::1", upstream_port).await;
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
            socks_udp_inbound(),
            Vec::new(),
            vec![socks_outbound("direct", socks_port, None, None)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_vmess_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let vmess_port = start_vmess_udp_upstream(upstream_port, id).await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![vmess_outbound("direct", vmess_port, id)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_tls_vmess_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let vmess_port = start_tls_vmess_udp_upstream(upstream_port, id).await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![tls_vmess_outbound("direct", vmess_port, id)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_vless_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let vless_port = start_vless_udp_upstream(upstream_port, id).await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![vless_outbound("direct", vless_port, id)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn vmess_udp_payload_times_out_when_upstream_does_not_respond() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let vmess_port = start_unresponsive_vmess_udp_upstream(id).await;
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };

        assert!(matches!(
            send_socks_udp_payload(
                &vmess_outbound("direct", vmess_port, id),
                &destination,
                b"ping"
            )
            .await,
            Err(CoreError::Timeout)
        ));
    }

    #[tokio::test]
    async fn socks5_udp_associate_uses_proxy_host_for_unspecified_socks_upstream_relay() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let socks_port = start_socks_udp_upstream_with_unspecified_relay().await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![socks_outbound("direct", socks_port, None, None)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_uses_ipv6_proxy_host_for_unspecified_socks_upstream_relay() {
        let (upstream_port, upstream_task) = start_udp_dns_server_on("::1", b"pong".to_vec()).await;
        let socks_port = start_ipv6_socks_udp_upstream_with_unspecified_relay().await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![socks_outbound_with_address(
                "direct", "::1", socks_port, None, None,
            )],
        )
        .await;

        assert_socks_udp_round_trip_with_host(proxy_port, "::1", upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_tls_socks_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let socks_port = start_tls_socks_udp_upstream().await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![tls_socks_outbound("direct", socks_port, None, None)],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    async fn assert_socks_udp_round_trip(proxy_port: u16, upstream_port: u16) {
        assert_socks_udp_round_trip_with_host(proxy_port, "127.0.0.1", upstream_port).await;
    }

    async fn assert_socks_udp_round_trip_with_host(
        proxy_port: u16,
        host: &str,
        upstream_port: u16,
    ) {
        assert_socks_udp_round_trip_through_proxy("127.0.0.1", proxy_port, host, upstream_port)
            .await;
    }

    async fn assert_socks_udp_round_trip_through_proxy(
        proxy_host: &str,
        proxy_port: u16,
        host: &str,
        upstream_port: u16,
    ) {
        let destination = Destination {
            host: DestinationHost::parse(host).unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let (_tcp, udp, udp_relay) = start_socks_udp_associate_on(proxy_host, proxy_port).await;
        let packet = encode_socks_udp_packet(&destination, b"ping").unwrap();
        udp.send_to(&packet, udp_relay).await.unwrap();
        let mut buffer = [0_u8; 128];
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.payload, b"pong");
    }

    async fn assert_socks_udp_no_response(proxy_port: u16, host: &str, upstream_port: u16) {
        let destination = Destination {
            host: DestinationHost::parse(host).unwrap(),
            port: upstream_port,
            network: Network::Udp,
        };
        let (_tcp, udp, udp_port) = start_socks_udp_associate(proxy_port).await;
        let packet = encode_socks_udp_packet(&destination, b"ping").unwrap();
        udp.send_to(&packet, ("127.0.0.1", udp_port)).await.unwrap();
        let mut buffer = [0_u8; 128];
        assert!(
            timeout(Duration::from_millis(100), udp.recv(&mut buffer))
                .await
                .is_err()
        );
    }

    fn udp_route_rule(
        domain: Vec<&str>,
        ip: Vec<&str>,
        outbound_tag: &str,
        port: u16,
    ) -> xrs_config::RoutingRuleConfig {
        xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(port.into()),
            domain: domain.into_iter().map(str::to_owned).collect(),
            ip: ip.into_iter().map(str::to_owned).collect(),
            source: Vec::new(),
            source_port: None,
            network: Some("udp".into()),
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some(outbound_tag.to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    async fn start_socks_udp_associate(proxy_port: u16) -> (TcpStream, UdpSocket, u16) {
        let (tcp, udp, udp_relay) = start_socks_udp_associate_on("127.0.0.1", proxy_port).await;
        assert!(udp_relay.ip().is_ipv4());
        (tcp, udp, udp_relay.port())
    }

    async fn start_socks_udp_associate_on(
        proxy_host: &str,
        proxy_port: u16,
    ) -> (TcpStream, UdpSocket, SocketAddr) {
        let mut tcp = TcpStream::connect((proxy_host, proxy_port)).await.unwrap();
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        tcp.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut prefix = [0_u8; 4];
        tcp.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix[..3], [0x05, 0x00, 0x00]);
        let udp_relay = match prefix[3] {
            0x01 => {
                let mut address = [0_u8; 4];
                tcp.read_exact(&mut address).await.unwrap();
                let port = read_test_socks_port(&mut tcp).await;
                SocketAddr::new(IpAddr::from(address), port)
            }
            0x04 => {
                let mut address = [0_u8; 16];
                tcp.read_exact(&mut address).await.unwrap();
                let port = read_test_socks_port(&mut tcp).await;
                SocketAddr::new(IpAddr::from(address), port)
            }
            address_type => panic!("unexpected SOCKS relay address type {address_type}"),
        };
        let udp_bind = if udp_relay.ip().is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        (tcp, UdpSocket::bind(udp_bind).await.unwrap(), udp_relay)
    }

    async fn read_test_socks_port(stream: &mut TcpStream) -> u16 {
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        u16::from_be_bytes(port)
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

    #[tokio::test]
    async fn shadowsocks_udp_inbound_drops_udp_through_blackhole() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", 53);
        let outbounds = vec![
            freedom_outbound_with_domain_strategy(None),
            OutboundConfig {
                tag: "blocked".to_owned(),
                protocol: OutboundProtocol::Blackhole,
                send_through: None,
                proxy_settings: None,
                settings: None,
                stream_settings: None,
                mux: None,
                extra: Default::default(),
            },
        ];
        let (proxy_port, proxy_task) = start_shadowsocks_udp_proxy_with_outbounds(
            "secret",
            vec![rule.clone()],
            outbounds.clone(),
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let key = shadowsocks_password_key("secret");
        let blocked_destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };
        let blocked_request =
            encrypt_shadowsocks_udp_packet(key, &blocked_destination, b"blocked").unwrap();
        let direct_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let direct_context = ShadowsocksUdpInboundContext {
            key,
            inbound_tag: "test-in".to_owned(),
            socket: direct_socket,
            router: Arc::new(
                Router::from_config(&RootConfig {
                    log: xrs_config::LogConfig::default(),
                    inbounds: vec![shadowsocks_udp_inbound("secret")],
                    outbounds: outbounds.clone(),
                    routing: xrs_config::RoutingConfig {
                        rules: vec![rule],
                        balancers: Vec::new(),
                        domain_strategy: None,
                        domain_matcher: None,
                        extra: Default::default(),
                    },
                    ..RootConfig::default()
                })
                .unwrap(),
            ),
            outbounds: Arc::new(
                outbounds
                    .iter()
                    .map(|outbound| (outbound.tag.clone(), outbound.clone()))
                    .collect::<HashMap<_, _>>(),
            ),
            dns_hosts: Arc::new(RuntimeDns::default()),
            counters: Arc::new(TrafficCounters::default()),
        };
        handle_shadowsocks_udp_packet(
            direct_context,
            "127.0.0.1:12345".parse().unwrap(),
            blocked_request.clone(),
        )
        .await
        .unwrap();
        client
            .send_to(&blocked_request, ("127.0.0.1", proxy_port))
            .await
            .unwrap();
        let mut response = [0_u8; 65535];
        assert!(
            timeout(Duration::from_millis(100), client.recv(&mut response))
                .await
                .is_err()
        );

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
        assert_eq!(accepted.user.as_deref(), Some("user"));
    }

    #[tokio::test]
    async fn accepts_http_basic_proxy_auth_case_insensitive_scheme() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Http, "user", "pass");
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: bAsIc dXNlcjpwYXNz\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert_eq!(accepted.user.as_deref(), Some("user"));
    }

    #[tokio::test]
    async fn rejects_http_basic_proxy_auth_with_tab_separator() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Http, "user", "pass");
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await });

        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic\tdXNlcjpwYXNz\r\n\r\n",
            )
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
    async fn strips_proxy_only_headers_from_http_absolute_form_request() {
        let (mut client, mut server) = duplex(1024);
        let inbound = auth_inbound(InboundProtocol::Http, "user", "pass");
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(
                b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\nUser-Agent: xrs-test\r\n\r\n",
            )
            .await
            .unwrap();

        let accepted = task.await.unwrap();
        let forwarded = String::from_utf8(accepted.remote_prefix).unwrap();
        assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Host: example.com:8080\r\n"));
        assert!(forwarded.contains("User-Agent: xrs-test\r\n"));
        assert!(!forwarded.contains("Proxy-Authorization:"));
        assert!(!forwarded.contains("Proxy-Connection:"));
    }

    #[tokio::test]
    async fn rewrites_query_only_http_absolute_form_to_root_origin_form() {
        let (mut client, mut server) = duplex(1024);
        let inbound = test_inbound(InboundProtocol::Http);
        let task = tokio::spawn(async move { accept_http(&mut server, &inbound).await.unwrap() });

        client
            .write_all(
                b"GET http://example.com:8080?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
            )
            .await
            .unwrap();

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 8080);
        assert!(
            accepted
                .remote_prefix
                .starts_with(b"GET /?q=1 HTTP/1.1\r\n")
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
        assert_eq!(accepted.destination.network, Network::Tcp);
        assert!(accepted.remote_prefix.is_empty());
    }

    #[tokio::test]
    async fn accepts_trojan_domain_udp_command() {
        let (mut client, mut server) = duplex(1024);
        let inbound = trojan_inbound("secret");
        let task = tokio::spawn(async move { accept_trojan(&mut server, &inbound).await.unwrap() });

        write_trojan_command(&mut client, "secret", 0x03, "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert_eq!(accepted.destination.network, Network::Udp);
        assert!(accepted.remote_prefix.is_empty());
    }

    #[tokio::test]
    async fn accepts_trojan_client_email_user() {
        let (mut client, mut server) = duplex(1024);
        let mut inbound = trojan_inbound("secret");
        inbound.settings.as_mut().unwrap().clients[0].email = Some("alice@example.com".to_owned());
        let task = tokio::spawn(async move { accept_trojan(&mut server, &inbound).await.unwrap() });

        write_trojan_connect(&mut client, "secret", "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.user.as_deref(), Some("alice@example.com"));
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
    async fn rejects_unsupported_trojan_command() {
        let (mut client, mut server) = duplex(1024);
        let inbound = trojan_inbound("secret");
        let task = tokio::spawn(async move { accept_trojan(&mut server, &inbound).await });

        write_trojan_command(&mut client, "secret", 0x02, "example.com", 443).await;

        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::UnsupportedTrojanCommand(0x02))
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
        assert_eq!(accepted.destination.network, Network::Tcp);
        assert!(accepted.remote_prefix.is_empty());
        assert_eq!(accepted.client_prefix, [0, 0]);
    }

    #[tokio::test]
    async fn accepts_vless_domain_udp_command() {
        let (mut client, mut server) = duplex(1024);
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let inbound = vless_inbound(id);
        let task = tokio::spawn(async move { accept_vless(&mut server, &inbound).await.unwrap() });

        write_vless_command(&mut client, id, 0x02, "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.destination.host.to_string(), "example.com");
        assert_eq!(accepted.destination.port, 443);
        assert_eq!(accepted.destination.network, Network::Udp);
        assert!(accepted.remote_prefix.is_empty());
        assert_eq!(accepted.client_prefix, [0, 0]);
    }

    #[tokio::test]
    async fn accepts_vless_client_email_user() {
        let (mut client, mut server) = duplex(1024);
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let mut inbound = vless_inbound(id);
        inbound.settings.as_mut().unwrap().clients[0].email = Some("alice@example.com".to_owned());
        let task = tokio::spawn(async move { accept_vless(&mut server, &inbound).await.unwrap() });

        write_vless_connect(&mut client, id, "example.com", 443).await;

        let accepted = task.await.unwrap();
        assert_eq!(accepted.user.as_deref(), Some("alice@example.com"));
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
    async fn rejects_unsupported_vless_command() {
        let (mut client, mut server) = duplex(1024);
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let inbound = vless_inbound(id);
        let task = tokio::spawn(async move { accept_vless(&mut server, &inbound).await });

        write_vless_command(&mut client, id, 0x03, "example.com", 443).await;

        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::UnsupportedVlessCommand(0x03))
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
    async fn trojan_udp_command_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let (proxy_port, proxy_task) = start_trojan_proxy("secret").await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_trojan_command(&mut client, "secret", 0x03, "127.0.0.1", upstream_port).await;
        write_trojan_udp_packet(&mut client, "127.0.0.1", upstream_port, b"ping").await;

        let (_, payload) = read_trojan_udp_packet(&mut client).await;
        assert_eq!(&payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn trojan_udp_quic_sniffing_protocol_routes_quic_packets() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let mut inbound = trojan_inbound("secret");
        inbound.sniffing = Some(sniffing_config("quic"));
        let mut protocol_rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        protocol_rule.protocol = vec!["quic".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_trojan_command(&mut client, "secret", 0x03, "127.0.0.1", upstream_port).await;
        write_trojan_udp_packet(
            &mut client,
            "127.0.0.1",
            upstream_port,
            quic_initial_packet(),
        )
        .await;

        let mut prefix = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(100), client.read_exact(&mut prefix))
                .await
                .is_err()
        );
        assert!(!upstream_task.is_finished());
        upstream_task.abort();
        proxy_task.abort();
    }

    #[tokio::test]
    async fn trojan_udp_reuses_udp_source_for_same_destination() {
        let (upstream_port, upstream_task) = start_stateful_udp_server().await;
        let (proxy_port, proxy_task) = start_trojan_proxy("secret").await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_trojan_command(&mut client, "secret", 0x03, "127.0.0.1", upstream_port).await;
        write_trojan_udp_packet(&mut client, "127.0.0.1", upstream_port, b"one").await;
        let (_, first) = read_trojan_udp_packet(&mut client).await;
        assert_eq!(&first, b"ack1");
        write_trojan_udp_packet(&mut client, "127.0.0.1", upstream_port, b"two").await;
        let (_, second) = read_trojan_udp_packet(&mut client).await;
        assert_eq!(&second, b"ack2");
        assert_eq!(
            upstream_task.await.unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn trojan_udp_no_response_datagram_does_not_block_later_datagrams() {
        let (upstream_port, upstream_task) = start_delayed_response_udp_server().await;
        let (proxy_port, proxy_task) = start_trojan_proxy("secret").await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_trojan_command(&mut client, "secret", 0x03, "127.0.0.1", upstream_port).await;
        write_trojan_udp_packet(&mut client, "127.0.0.1", upstream_port, b"silent").await;
        write_trojan_udp_packet(&mut client, "127.0.0.1", upstream_port, b"loud").await;

        let (_, payload) = timeout(Duration::from_secs(1), read_trojan_udp_packet(&mut client))
            .await
            .unwrap();
        assert_eq!(&payload, b"ack");
        assert_eq!(
            upstream_task.await.unwrap(),
            vec![b"silent".to_vec(), b"loud".to_vec()]
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_inbound_reaches_echo_server_through_trojan_upstream() {
        let echo_port = start_echo_server().await;
        let upstream_port = start_trojan_upstream(echo_port, "secret").await;
        let outbound = trojan_outbound("upstream", upstream_port, "secret");
        assert_socks5_inbound_reaches_echo_server_through_outbound(echo_port, outbound, b"trou")
            .await;
    }

    #[tokio::test]
    async fn socks5_udp_associate_reaches_udp_server_through_trojan_upstream() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let trojan_port = start_trojan_udp_upstream(upstream_port, "secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![trojan_outbound("direct", trojan_port, "secret")],
        )
        .await;

        assert_socks_udp_round_trip(proxy_port, upstream_port).await;
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_trojan_response_uses_upstream_destination() {
        let trojan_port = start_trojan_udp_response_destination_upstream("secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![trojan_outbound("direct", trojan_port, "secret")],
        )
        .await;
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };
        let (_tcp, udp, udp_relay) = start_socks_udp_associate(proxy_port).await;
        let packet = encode_socks_udp_packet(&destination, b"ping").unwrap();
        udp.send_to(&packet, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let mut buffer = [0_u8; 128];
        let length = timeout(DNS_TIMEOUT, udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.destination.host.to_string(), "example.com");
        assert_eq!(parsed.destination.port, 5353);
        assert_eq!(parsed.payload, b"pong");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks5_udp_trojan_no_response_does_not_block_later_datagrams() {
        let trojan_port = start_silent_then_loud_trojan_udp_upstream("secret").await;
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            socks_udp_inbound(),
            Vec::new(),
            vec![trojan_outbound("direct", trojan_port, "secret")],
        )
        .await;
        let destination = Destination {
            host: DestinationHost::parse("127.0.0.1").unwrap(),
            port: 53,
            network: Network::Udp,
        };
        let (_tcp, udp, udp_relay) = start_socks_udp_associate(proxy_port).await;
        let first = encode_socks_udp_packet(&destination, b"silent").unwrap();
        udp.send_to(&first, ("127.0.0.1", udp_relay)).await.unwrap();
        let second = encode_socks_udp_packet(&destination, b"loud").unwrap();
        udp.send_to(&second, ("127.0.0.1", udp_relay))
            .await
            .unwrap();
        let mut buffer = [0_u8; 128];
        let length = timeout(Duration::from_secs(1), udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_socks_udp_packet(&buffer[..length]).unwrap();
        assert_eq!(parsed.payload, b"pong");
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
    async fn vless_udp_command_reaches_udp_server_through_freedom() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_vless_proxy(id).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_vless_command(&mut client, id, 0x02, "127.0.0.1", upstream_port).await;
        let mut response_header = [0_u8; 2];
        client.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0, 0]);
        write_vless_udp_packet(&mut client, b"ping").await;

        let payload = read_vless_udp_packet(&mut client).await;
        assert_eq!(&payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn vless_udp_command_drops_udp_through_blackhole() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            vless_inbound(id),
            vec![rule],
            vec![blackhole_outbound("blocked")],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_vless_command(&mut client, id, 0x02, "127.0.0.1", upstream_port).await;
        let mut response_header = [0_u8; 2];
        client.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0, 0]);
        write_vless_udp_packet(&mut client, b"ping").await;

        let mut length = [0_u8; 2];
        assert!(
            timeout(Duration::from_millis(100), client.read_exact(&mut length))
                .await
                .is_err()
        );
        upstream_task.abort();
        proxy_task.abort();
    }

    #[tokio::test]
    async fn vless_udp_quic_sniffing_protocol_routes_quic_packets() {
        let (upstream_port, upstream_task) = start_udp_dns_server(b"pong".to_vec()).await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let mut inbound = vless_inbound(id);
        inbound.sniffing = Some(sniffing_config("quic"));
        let mut protocol_rule = udp_route_rule(Vec::new(), Vec::new(), "blocked", upstream_port);
        protocol_rule.protocol = vec!["quic".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        write_vless_command(&mut client, id, 0x02, "127.0.0.1", upstream_port).await;
        let mut response_header = [0_u8; 2];
        client.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0, 0]);
        write_vless_udp_packet(&mut client, quic_initial_packet()).await;

        let mut length = [0_u8; 2];
        assert!(
            timeout(Duration::from_millis(100), client.read_exact(&mut length))
                .await
                .is_err()
        );
        assert!(!upstream_task.is_finished());
        upstream_task.abort();
        proxy_task.abort();
    }

    #[tokio::test]
    async fn freedom_redirect_preserves_destination_network() {
        let mut outbound = freedom_outbound_with_domain_strategy(None);
        outbound.settings = Some(xrs_config::OutboundSettings {
            servers: Vec::new(),
            response: None,
            redirect: Some("127.0.0.1:8443".to_owned()),
            domain_strategy: None,
            target_strategy: None,
            proxy_protocol: None,
            user_level: None,
            fragment: None,
            noises: None,
            final_rules: None,
            extra: std::collections::BTreeMap::new(),
        });
        let destination = Destination {
            host: DestinationHost::parse("192.0.2.1").unwrap(),
            port: 443,
            network: Network::Udp,
        };

        let resolved = freedom_destination(&outbound, &destination).await.unwrap();

        assert_eq!(resolved.host, DestinationHost::parse("127.0.0.1").unwrap());
        assert_eq!(resolved.port, 8443);
        assert_eq!(resolved.network, Network::Udp);
    }

    #[tokio::test]
    async fn freedom_domain_strategy_use_ip_resolves_domain_targets() {
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        let destination = Destination::tcp(DestinationHost::parse("localhost").unwrap(), 443);

        let resolved = freedom_destination(&outbound, &destination).await.unwrap();

        assert!(matches!(resolved.host, DestinationHost::Ip(_)));
        assert_eq!(resolved.port, 443);
    }

    #[tokio::test]
    async fn freedom_sockopt_domain_strategy_use_ip_resolves_domain_targets() {
        let mut outbound = freedom_outbound_with_domain_strategy(None);
        outbound.stream_settings = Some(sockopt_domain_strategy_stream_settings("UseIP"));
        let destination = Destination::tcp(DestinationHost::parse("localhost").unwrap(), 443);

        let resolved = freedom_destination(&outbound, &destination).await.unwrap();

        assert!(matches!(resolved.host, DestinationHost::Ip(_)));
        assert_eq!(resolved.port, 443);
    }

    #[tokio::test]
    async fn freedom_sockopt_domain_strategy_ip_if_non_match_resolves_domain_targets() {
        let mut outbound = freedom_outbound_with_domain_strategy(None);
        outbound.stream_settings = Some(sockopt_domain_strategy_stream_settings("IPIfNonMatch"));
        let destination = Destination::tcp(DestinationHost::parse("localhost").unwrap(), 443);

        let resolved = freedom_destination(&outbound, &destination).await.unwrap();

        assert!(matches!(resolved.host, DestinationHost::Ip(_)));
        assert_eq!(resolved.port, 443);
    }

    #[tokio::test]
    async fn freedom_domain_strategy_uses_top_level_dns_hosts_before_system_dns() {
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        let destination = Destination::tcp(DestinationHost::parse("Mapped.Test.").unwrap(), 443);
        let dns_hosts = Arc::new(RuntimeDns {
            hosts: HashMap::from([(
                "mapped.test".to_owned(),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )]),
            servers: Vec::new(),
            query_strategy: None,
            disable_fallback: false,
            disable_fallback_if_match: false,
        });

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert_eq!(resolved.port, 443);
    }

    #[tokio::test]
    async fn freedom_domain_strategy_as_is_keeps_domain_targets() {
        let outbound = freedom_outbound_with_domain_strategy(Some("AsIs"));
        let destination = Destination::tcp(DestinationHost::parse("localhost").unwrap(), 443);

        let resolved = freedom_destination(&outbound, &destination).await.unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Domain("localhost".to_owned())
        );
        assert_eq!(resolved.port, 443);
    }

    #[tokio::test]
    async fn freedom_domain_strategy_as_is_ignores_top_level_dns_hosts() {
        let outbound = freedom_outbound_with_domain_strategy(Some("AsIs"));
        let destination = Destination::tcp(DestinationHost::parse("mapped.test").unwrap(), 443);
        let dns_hosts = Arc::new(RuntimeDns {
            hosts: HashMap::from([(
                "mapped.test".to_owned(),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )]),
            servers: Vec::new(),
            query_strategy: None,
            disable_fallback: false,
            disable_fallback_if_match: false,
        });

        let resolved = freedom_destination_with_dns_hosts(&outbound, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(
            resolved.host,
            DestinationHost::Domain("mapped.test".to_owned())
        );
        assert_eq!(resolved.port, 443);
    }

    #[test]
    fn freedom_domain_strategy_use_ipv4_selects_ipv4_targets() {
        let addresses = [
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(Some("UseIPv4"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv4());
    }

    #[test]
    fn freedom_sockopt_domain_strategy_use_ipv4_selects_ipv4_targets() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: None,
            stream_settings: Some(sockopt_domain_strategy_stream_settings("UseIPv4")),
            mux: None,
            extra: Default::default(),
        };
        let strategy = outbound
            .settings
            .as_ref()
            .and_then(|settings| {
                settings
                    .target_strategy
                    .as_deref()
                    .or(settings.domain_strategy.as_deref())
            })
            .or_else(|| {
                outbound
                    .stream_settings
                    .as_ref()
                    .and_then(|settings| settings.sockopt.as_ref())
                    .and_then(|sockopt| sockopt.domain_strategy.as_deref())
            });
        let addresses = [
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(strategy, addresses).unwrap().unwrap();

        assert!(address.ip().is_ipv4());
    }

    #[test]
    fn freedom_settings_domain_strategy_overrides_sockopt_domain_strategy() {
        let mut outbound = freedom_outbound_with_domain_strategy(Some("AsIs"));
        outbound.stream_settings = Some(sockopt_domain_strategy_stream_settings("UseIP"));
        let strategy = outbound
            .settings
            .as_ref()
            .and_then(|settings| {
                settings
                    .target_strategy
                    .as_deref()
                    .or(settings.domain_strategy.as_deref())
            })
            .or_else(|| {
                outbound
                    .stream_settings
                    .as_ref()
                    .and_then(|settings| settings.sockopt.as_ref())
                    .and_then(|sockopt| sockopt.domain_strategy.as_deref())
            });

        assert_eq!(strategy, Some("AsIs"));
    }

    #[test]
    fn freedom_target_strategy_overrides_domain_strategy() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: Vec::new(),
                response: None,
                redirect: None,
                domain_strategy: Some("UseIPv4".to_owned()),
                target_strategy: Some("UseIPv6".to_owned()),
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let strategy = outbound.settings.as_ref().and_then(|settings| {
            settings
                .target_strategy
                .as_deref()
                .or(settings.domain_strategy.as_deref())
        });
        let addresses = [
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(strategy, addresses).unwrap().unwrap();

        assert!(address.ip().is_ipv6());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv4_rejects_ipv6_only_targets() {
        let addresses = [SocketAddr::from((
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443,
        ))];

        assert!(matches!(
            pick_freedom_address(Some("UseIPv4"), addresses),
            Err(CoreError::NoFreedomAddressForDomainStrategy(strategy)) if strategy == "UseIPv4"
        ));
    }

    #[test]
    fn freedom_domain_strategy_use_ipv6_selects_ipv6_targets() {
        let addresses = [
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(Some("UseIPv6"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv6());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv6_rejects_ipv4_only_targets() {
        let addresses = [SocketAddr::from(([127, 0, 0, 1], 443))];

        assert!(matches!(
            pick_freedom_address(Some("UseIPv6"), addresses),
            Err(CoreError::NoFreedomAddressForDomainStrategy(strategy)) if strategy == "UseIPv6"
        ));
    }

    #[test]
    fn socks_udp_unspecified_ipv6_relay_prefers_ipv6_upstream_address() {
        let addresses = [
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
        ];

        let address = pick_udp_upstream_address(addresses, Some(IpAddr::from([0_u16; 8]))).unwrap();

        assert!(address.ip().is_ipv6());
    }

    #[test]
    fn socks_udp_unspecified_ipv4_relay_prefers_ipv4_upstream_address() {
        let addresses = [
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 443)),
        ];

        let address =
            pick_udp_upstream_address(addresses, Some(IpAddr::from([0, 0, 0, 0]))).unwrap();

        assert!(address.ip().is_ipv4());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv4v6_prefers_ipv4_targets() {
        let addresses = [
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(Some("UseIPv4v6"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv4());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv4v6_falls_back_to_ipv6_targets() {
        let addresses = [SocketAddr::from((
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443,
        ))];

        let address = pick_freedom_address(Some("UseIPv4v6"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv6());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv6v4_prefers_ipv6_targets() {
        let addresses = [
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)),
        ];

        let address = pick_freedom_address(Some("UseIPv6v4"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv6());
    }

    #[test]
    fn freedom_domain_strategy_use_ipv6v4_falls_back_to_ipv4_targets() {
        let addresses = [SocketAddr::from(([127, 0, 0, 1], 443))];

        let address = pick_freedom_address(Some("UseIPv6v4"), addresses)
            .unwrap()
            .unwrap();

        assert!(address.ip().is_ipv4());
    }

    #[tokio::test]
    async fn freedom_udp_uses_top_level_dns_hosts_before_system_dns() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 32];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(b"pong", peer).await.unwrap();
            buffer[..length].to_vec()
        });
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIP"));
        let destination = Destination {
            host: DestinationHost::parse("mapped.test").unwrap(),
            port,
            network: Network::Udp,
        };
        let dns_hosts = Arc::new(RuntimeDns {
            hosts: HashMap::from([(
                "mapped.test".to_owned(),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )]),
            servers: Vec::new(),
            query_strategy: None,
            disable_fallback: false,
            disable_fallback_if_match: false,
        });

        let response =
            send_socks_udp_payload_with_dns_hosts(&outbound, &destination, b"ping", &dns_hosts)
                .await
                .unwrap();

        assert_eq!(response.payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn freedom_udp_domain_strategy_use_ipv6v4_reaches_ipv6_target() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 32];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(b"pong", peer).await.unwrap();
            buffer[..length].to_vec()
        });
        let outbound = freedom_outbound_with_domain_strategy(Some("UseIPv6v4"));
        let destination = Destination {
            host: DestinationHost::Ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            port,
            network: Network::Udp,
        };

        let response = send_socks_udp_payload(&outbound, &destination, b"ping")
            .await
            .unwrap();

        assert_eq!(response.payload, b"pong");
        assert_eq!(upstream_task.await.unwrap(), b"ping");
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
            send_through: None,
            proxy_settings: None,
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
            extra: Default::default(),
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

    #[tokio::test]
    async fn socks_inbound_with_raw_stream_settings_reaches_echo_server_through_freedom() {
        let echo_port = start_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(raw_tcp_stream_settings("raw"));
        let (proxy_port, proxy_task) = start_proxy(inbound, Vec::new()).await;

        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"raw!").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_reaches_echo_server_through_raw_tcp_freedom_outbound() {
        let echo_port = start_echo_server().await;
        let mut outbound = freedom_outbound_with_domain_strategy(None);
        outbound.stream_settings = Some(raw_tcp_stream_settings("tcp"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Socks),
            Vec::new(),
            vec![outbound],
        )
        .await;

        assert_socks_client_echo(proxy_port, "127.0.0.1", echo_port, b"tcp!").await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn apply_tcp_no_delay_sets_stream_socket_option() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        apply_tcp_no_delay(&client, Some(&tcp_no_delay_stream_settings())).unwrap();

        assert!(client.nodelay().unwrap());
        drop(client);
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn apply_tcp_keepalive_accepts_configured_sockopt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        apply_tcp_keepalive(&client, Some(&tcp_keepalive_stream_settings())).unwrap();

        drop(client);
        let _ = server.await.unwrap();
    }

    #[test]
    fn tcp_keepalive_duration_options_ignore_zero_values() {
        let settings = zero_tcp_keepalive_stream_settings();
        let sockopt = settings.sockopt.as_ref().unwrap();

        let options = tcp_keepalive_duration_options(sockopt);

        assert_eq!(options, (None, None));
    }

    #[test]
    fn tcp_user_timeout_duration_option_uses_positive_milliseconds() {
        let settings = tcp_user_timeout_stream_settings();
        let sockopt = settings.sockopt.as_ref().unwrap();

        let timeout = tcp_user_timeout_duration_option(sockopt);

        assert_eq!(timeout, Some(Duration::from_millis(1000)));
    }

    #[test]
    fn tcp_user_timeout_duration_option_ignores_zero_values() {
        let settings = zero_tcp_user_timeout_stream_settings();
        let sockopt = settings.sockopt.as_ref().unwrap();

        let timeout = tcp_user_timeout_duration_option(sockopt);

        assert_eq!(timeout, None);
    }

    #[test]
    fn tcp_fast_open_enabled_reads_sockopt_flag() {
        let settings = tcp_fast_open_stream_settings();

        assert!(tcp_fast_open_enabled(Some(&settings)));
        assert!(!tcp_fast_open_enabled(None));
    }

    #[test]
    fn tcp_fast_open_uses_preconfigured_socket_path() {
        let settings = tcp_fast_open_stream_settings();

        assert!(tcp_connect_needs_preconfigured_socket(
            Some(&settings),
            None
        ));
        assert!(tcp_connect_needs_preconfigured_socket(
            None,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        ));
        assert!(!tcp_connect_needs_preconfigured_socket(None, None));
    }

    #[test]
    fn tcp_sockopt_domain_strategy_uses_preconfigured_socket_path() {
        for strategy in ["UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4"] {
            let settings = sockopt_domain_strategy_stream_settings(strategy);

            assert!(tcp_connect_needs_preconfigured_socket(
                Some(&settings),
                None
            ));
        }
    }

    #[test]
    fn compatible_tcp_remotes_preserve_all_matching_addresses() {
        let remotes = vec![
            SocketAddr::from(([127, 0, 0, 1], 1080)),
            SocketAddr::from(([127, 0, 0, 2], 1080)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1080)),
        ];

        assert_eq!(
            compatible_tcp_remotes(
                remotes.clone(),
                Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                None
            ),
            remotes[..2]
        );
        assert_eq!(compatible_tcp_remotes(remotes.clone(), None, None), remotes);
    }

    #[test]
    fn compatible_tcp_remotes_honor_sockopt_domain_strategy() {
        let ipv6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1080));
        let ipv4_a = SocketAddr::from(([127, 0, 0, 1], 1080));
        let ipv4_b = SocketAddr::from(([127, 0, 0, 2], 1080));
        let remotes = vec![ipv6, ipv4_a, ipv4_b];

        for (strategy, expected) in [
            ("UseIPv4", vec![ipv4_a, ipv4_b]),
            ("UseIPv6", vec![ipv6]),
            ("UseIPv4v6", vec![ipv4_a, ipv4_b, ipv6]),
            ("UseIPv6v4", vec![ipv6, ipv4_a, ipv4_b]),
        ] {
            let settings = sockopt_domain_strategy_stream_settings(strategy);

            assert_eq!(
                compatible_tcp_remotes(remotes.clone(), None, Some(&settings)),
                expected
            );
        }
    }

    #[test]
    fn compatible_tcp_remotes_apply_source_family_before_sockopt_domain_strategy() {
        let remotes = vec![
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1080)),
            SocketAddr::from(([127, 0, 0, 1], 1080)),
        ];
        let use_ipv4 = sockopt_domain_strategy_stream_settings("UseIPv4");
        let use_ipv6 = sockopt_domain_strategy_stream_settings("UseIPv6");

        assert!(
            compatible_tcp_remotes(
                remotes.clone(),
                Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                Some(&use_ipv6)
            )
            .is_empty()
        );
        assert!(
            compatible_tcp_remotes(
                remotes,
                Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
                Some(&use_ipv4)
            )
            .is_empty()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn apply_preconnect_tcp_socket_options_enables_tcp_fast_open() {
        use nix::sys::socket::getsockopt;

        let socket = TcpSocket::new_v4().unwrap();
        let settings = tcp_fast_open_stream_settings();

        apply_preconnect_tcp_socket_options(&socket, Some(&settings)).unwrap();

        assert!(getsockopt(&socket, TcpFastOpenConnect).unwrap());
    }

    #[tokio::test]
    async fn freedom_outbound_applies_tcp_no_delay_sockopt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut outbound = freedom_outbound_with_domain_strategy(None);
        outbound.stream_settings = Some(tcp_no_delay_stream_settings());
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let stream = connect_freedom(&outbound, &destination, None)
            .await
            .unwrap();

        match stream {
            OutboundStream::Tcp(stream) => assert!(stream.nodelay().unwrap()),
            OutboundStream::Tls(_) | OutboundStream::NestedTls(_) => {
                panic!("unexpected TLS stream")
            }
        }
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_outbound_applies_tcp_no_delay_sockopt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut outbound = socks_outbound("proxy", port, None, None);
        outbound.stream_settings = Some(tcp_no_delay_stream_settings());
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let stream = connect_outbound_stream_with_source(&outbound, &destination, None)
            .await
            .unwrap();

        match stream {
            OutboundStream::Tcp(stream) => assert!(stream.nodelay().unwrap()),
            OutboundStream::Tls(_) | OutboundStream::NestedTls(_) => {
                panic!("unexpected TLS stream")
            }
        }
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn inbound_applies_tcp_no_delay_sockopt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(tcp_no_delay_stream_settings());
        let accept = tokio::spawn(async move {
            let accepted = accept_inbound_client(&listener, &inbound).await.unwrap();
            accepted.stream.nodelay().unwrap()
        });

        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        assert!(accept.await.unwrap());
        drop(client);
    }

    #[tokio::test]
    async fn freedom_send_through_binds_tcp_source() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
            peer.ip()
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: Some("127.0.0.1".to_owned()),
            proxy_settings: None,
            settings: None,
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let mut stream = connect_freedom(&outbound, &destination, None)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, *b"ping");
        assert_eq!(
            server.await.unwrap(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
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
            send_through: None,
            proxy_settings: None,
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
            extra: Default::default(),
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let stream = connect_freedom(&outbound, &destination, None)
            .await
            .unwrap();
        match stream {
            OutboundStream::Tls(stream) => {
                let selected = stream.get_ref().negotiated_alpn().unwrap();
                assert_eq!(selected, Some(b"h2".to_vec()));
            }
            OutboundStream::Tcp(_) => panic!("expected TLS stream"),
            OutboundStream::NestedTls(_) => panic!("unexpected nested TLS stream"),
        }
        let selected = server.await.unwrap();
        assert_eq!(selected, Some(b"h2".to_vec()));
    }

    #[tokio::test]
    async fn freedom_tls_to_ip_without_server_name_fails_before_connecting() {
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: None,
            stream_settings: Some(xrs_config::StreamSettingsConfig {
                security: Some("tls".to_owned()),
                tls_settings: Some(xrs_config::TlsSettingsConfig::default()),
                ..Default::default()
            }),
            mux: None,
            extra: Default::default(),
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), 9);

        assert!(matches!(
            connect_freedom(&outbound, &destination, None).await,
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

    #[test]
    fn freedom_proxy_protocol_v2_header_encodes_ipv4_addresses() {
        let source = SocketAddr::from(([127, 0, 0, 1], 12345));
        let destination = SocketAddr::from(([127, 0, 0, 1], 443));

        let header = proxy_protocol_v2_header(source, destination);

        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
        assert_eq!(&header[16..20], &[127, 0, 0, 1]);
        assert_eq!(&header[20..24], &[127, 0, 0, 1]);
        assert_eq!(&header[24..26], &12345_u16.to_be_bytes());
        assert_eq!(&header[26..28], &443_u16.to_be_bytes());
    }

    #[tokio::test]
    async fn freedom_proxy_protocol_v1_header_precedes_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                received.push(byte[0]);
                if received.ends_with(b"\r\n") {
                    break;
                }
            }
            let mut tls_byte = [0_u8; 1];
            stream.read_exact(&mut tls_byte).await.unwrap();
            (received, tls_byte[0])
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: Vec::new(),
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: Some(1),
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
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
            extra: Default::default(),
        };
        let destination = Destination::tcp(DestinationHost::parse("127.0.0.1").unwrap(), port);

        let connect_task = tokio::spawn(async move {
            connect_freedom(
                &outbound,
                &destination,
                Some(SocketAddr::from(([127, 0, 0, 1], 12345))),
            )
            .await
        });
        let (header, tls_byte) = server.await.unwrap();
        connect_task.abort();
        let header = String::from_utf8(header).unwrap();
        assert!(header.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 12345 "));
        assert_eq!(tls_byte, 0x16);
    }

    #[tokio::test]
    async fn freedom_proxy_protocol_v1_header_precedes_tcp_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                received.push(byte[0]);
                if received.ends_with(b"\r\nGET") {
                    break;
                }
            }
            String::from_utf8(received).unwrap()
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: Vec::new(),
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: Some(1),
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            test_inbound(InboundProtocol::Http),
            Vec::new(),
            vec![outbound],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let received = upstream_task.await.unwrap();
        assert!(received.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "));
        assert!(received.ends_with("\r\nGET"));
        proxy_task.abort();
    }

    #[tokio::test]
    async fn freedom_proxy_protocol_v1_header_precedes_payload_through_chained_socks_proxy() {
        let received = connect_freedom_through_socks_proxy_with_proxy_protocol(
            DestinationHost::parse("127.0.0.1").unwrap(),
            Some(SocketAddr::from(([127, 0, 0, 1], 12345))),
        )
        .await;

        assert!(received.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 12345 443"));
        assert!(received.ends_with("\r\nGET"));
    }

    #[tokio::test]
    async fn freedom_proxy_protocol_v1_unknown_header_precedes_payload_through_chained_socks_domain()
     {
        let received = connect_freedom_through_socks_proxy_with_proxy_protocol(
            DestinationHost::parse("example.test").unwrap(),
            Some(SocketAddr::from(([127, 0, 0, 1], 12345))),
        )
        .await;

        assert!(received.starts_with("PROXY UNKNOWN\r\nGET"));
    }

    async fn connect_freedom_through_socks_proxy_with_proxy_protocol(
        destination_host: DestinationHost,
        source: Option<SocketAddr>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let expected_host = destination_host.clone();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let destination = accept_socks5_request(&mut stream).await;
            assert_eq!(destination.host, expected_host);
            assert_eq!(destination.port, 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut received = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                received.push(byte[0]);
                if received.len() >= 5 && !received.starts_with(b"PROXY") {
                    break;
                }
                if received.ends_with(b"\r\nGET") {
                    break;
                }
            }
            String::from_utf8(received).unwrap()
        });
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: Some(xrs_config::ProxySettingsConfig {
                tag: Some("proxy".to_owned()),
                extra: std::collections::BTreeMap::new(),
            }),
            settings: Some(xrs_config::OutboundSettings {
                servers: Vec::new(),
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: Some(1),
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let proxy = socks_outbound("proxy", proxy_port, None, None);
        let dns_hosts = Arc::new(RuntimeDns::default());
        let destination = Destination::tcp(destination_host, 443);
        let mut remote = connect_freedom_for_outbound(
            &outbound,
            &destination,
            source,
            &HashMap::from([("proxy".to_owned(), proxy)]),
            &dns_hosts,
        )
        .await
        .unwrap();

        remote.write_all(b"GET /").await.unwrap();

        proxy_task.await.unwrap()
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_host_drives_domain_routing() {
        let http_port = start_http_server().await.0;
        let rule = blocked_example_rule();
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_door_http_sniffing_host_drives_domain_routing() {
        let (http_port, http_task) = start_http_server().await;
        let mut inbound = dokodemo_inbound("127.0.0.1", http_port, None);
        inbound.sniffing = Some(sniffing_config("http"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
        http_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_tls_sniffing_sni_drives_domain_routing() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("tls"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", tls_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let result = connector.connect("blocked.example", client).await;
        assert!(result.is_err());
        proxy_task.abort();
    }

    #[tokio::test]
    async fn http_connect_inbound_tls_sniffing_sni_drives_domain_routing() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Http);
        inbound.sniffing = Some(sniffing_config("tls"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(format!("CONNECT 127.0.0.1:{tls_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let result = connector.connect("blocked.example", client).await;
        assert!(result.is_err());
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_tls_sniffing_protocol_routes_tls_requests() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("tls");
        sniffing.route_only = true;
        inbound.sniffing = Some(sniffing);
        let mut protocol_rule = blocked_example_rule();
        protocol_rule.domain.clear();
        protocol_rule.protocol = vec!["tls".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", tls_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let result = connector.connect("allowed.example", client).await;
        assert!(result.is_err());
        proxy_task.abort();
    }

    #[tokio::test]
    async fn tls_sniffing_without_sni_still_classifies_protocol() {
        let client_hello_without_sni = [
            0x16, 0x03, 0x01, 0x00, 0x31, 0x01, 0x00, 0x00, 0x2d, 0x03, 0x03, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x0a,
        ];
        let mut stream = std::io::Cursor::new(client_hello_without_sni);
        let mut accepted = AcceptedInbound::new(Destination {
            host: DestinationHost::Ip("127.0.0.1".parse().unwrap()),
            port: 443,
            network: Network::Tcp,
        });

        let sniffed = sniff_tls_destination(&mut stream, &mut accepted, true, false, &[])
            .await
            .unwrap();

        assert!(sniffed);
        assert_eq!(accepted.protocol.as_deref(), Some("tls"));
        assert_eq!(accepted.remote_prefix, client_hello_without_sni);
    }

    #[tokio::test]
    async fn socks_inbound_dual_sniffing_tls_sni_drives_domain_routing() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config_with_overrides(["http", "tls"]));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", tls_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let result = connector.connect("blocked.example", client).await;
        assert!(result.is_err());
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_dual_sniffing_http_host_drives_domain_routing() {
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config_with_overrides(["http", "tls"]));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_domains_excluded_skips_domain_routing() {
        let (http_port, http_task) = start_http_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("http");
        sniffing.domains_excluded = vec!["blocked.example".to_owned()];
        inbound.sniffing = Some(sniffing);
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut http_response = Vec::new();
        client.read_to_end(&mut http_response).await.unwrap();
        assert!(String::from_utf8_lossy(&http_response).contains("200 OK"));
        assert_eq!(http_task.await.unwrap(), "GET / HTTP/1.1");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_protocol_routes_http_requests() {
        let hostless_port = start_echo_server().await;
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let mut protocol_rule = blocked_example_rule();
        protocol_rule.domain.clear();
        protocol_rule.protocol = vec!["http".to_owned()];
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;

        let mut hostless_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        hostless_client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        hostless_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut hostless_client, "127.0.0.1", hostless_port).await;
        let mut response = [0_u8; 10];
        hostless_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        hostless_client
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut closed = [0_u8; 1];
        let read = hostless_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);

        let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        http_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        http_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        http_client
            .write_all(b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = http_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_get_requests() {
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let mut attrs_rule = blocked_example_rule();
        attrs_rule.domain.clear();
        attrs_rule.attrs = Some("attrs[':method'] == 'GET'".into());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![attrs_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;

        let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        http_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        http_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        http_client
            .write_all(b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = http_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);

        let mut no_host_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        no_host_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        no_host_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut no_host_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        no_host_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        no_host_client
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = no_host_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_path_requests() {
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let mut attrs_rule = blocked_example_rule();
        attrs_rule.domain.clear();
        attrs_rule.attrs = Some("attrs[':path'] == '/blocked'".into());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![attrs_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;

        let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        http_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        http_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        http_client
            .write_all(b"GET /blocked HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = http_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_path_prefix_requests() {
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let mut attrs_rule = blocked_example_rule();
        attrs_rule.domain.clear();
        attrs_rule.attrs = Some("attrs[':path'].startswith('/blocked')".into());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![attrs_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;

        let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        http_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        http_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        http_client
            .write_all(b"GET /blocked/page HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = http_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_compound_requests() {
        for (attrs, path) in [
            (
                "attrs[':method'] == 'GET' && attrs[':path'] == '/blocked'",
                "/blocked",
            ),
            (
                "attrs[':path'] == '/blocked' && attrs[':method'] == 'GET'",
                "/blocked",
            ),
            (
                "attrs[':method'] == 'GET' && attrs[':path'].startswith('/blocked')",
                "/blocked/page",
            ),
            (
                "attrs[':path'].startswith('/blocked') && attrs[':method'] == 'GET'",
                "/blocked/page",
            ),
        ] {
            let http_port = start_http_server().await.0;
            let mut inbound = test_inbound(InboundProtocol::Socks);
            inbound.sniffing = Some(sniffing_config("http"));
            let mut attrs_rule = blocked_example_rule();
            attrs_rule.domain.clear();
            attrs_rule.attrs = Some(attrs.into());
            let (proxy_port, proxy_task) = start_proxy_with_outbounds(
                inbound,
                vec![attrs_rule],
                vec![
                    freedom_outbound_with_domain_strategy(None),
                    blackhole_outbound("blocked"),
                ],
            )
            .await;

            let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method = [0_u8; 2];
            http_client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, 0x00]);
            write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
            let mut response = [0_u8; 10];
            http_client.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0x00);
            http_client
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: allowed.example\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();

            let mut closed = [0_u8; 1];
            let read = http_client.read(&mut closed).await.unwrap();
            assert_eq!(read, 0);
            proxy_task.abort();
        }
    }

    #[tokio::test]
    async fn http_sniffing_omits_missing_request_path_attr() {
        let (mut client, mut server) = duplex(1024);
        server
            .write_all(b"GET\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();
        drop(server);
        let mut accepted = AcceptedInbound::new(Destination {
            host: DestinationHost::Domain("original.example".to_owned()),
            port: 80,
            network: Network::Tcp,
        });

        sniff_http_destination(&mut client, &mut accepted, true, false, &[])
            .await
            .unwrap();

        assert_eq!(accepted.attributes.get(":method"), Some(&"GET".to_owned()));
        assert!(!accepted.attributes.contains_key(":path"));
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_or_requests() {
        for request in [
            b"GET /allowed HTTP/1.1\r\nHost: allowed.example\r\n\r\n".as_slice(),
            b"POST /blocked HTTP/1.1\r\nHost: allowed.example\r\n\r\n".as_slice(),
        ] {
            let http_port = start_http_server().await.0;
            let mut inbound = test_inbound(InboundProtocol::Socks);
            inbound.sniffing = Some(sniffing_config("http"));
            let mut attrs_rule = blocked_example_rule();
            attrs_rule.domain.clear();
            attrs_rule.attrs =
                Some("attrs[':method'] == 'GET' || attrs[':path'] == '/blocked'".into());
            let (proxy_port, proxy_task) = start_proxy_with_outbounds(
                inbound,
                vec![attrs_rule],
                vec![
                    freedom_outbound_with_domain_strategy(None),
                    blackhole_outbound("blocked"),
                ],
            )
            .await;

            let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method = [0_u8; 2];
            http_client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, 0x00]);
            write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
            let mut response = [0_u8; 10];
            http_client.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0x00);
            http_client.write_all(request).await.unwrap();

            let mut closed = [0_u8; 1];
            let read = http_client.read(&mut closed).await.unwrap();
            assert_eq!(read, 0);
            proxy_task.abort();
        }
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_attrs_routes_path_inequality_requests() {
        let http_port = start_http_server().await.0;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("http"));
        let mut attrs_rule = blocked_example_rule();
        attrs_rule.domain.clear();
        attrs_rule.attrs = Some("attrs[':path'] != '/allowed'".into());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![attrs_rule],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;

        let mut http_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        http_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        http_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut http_client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        http_client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        http_client
            .write_all(b"GET /blocked HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            .await
            .unwrap();

        let mut closed = [0_u8; 1];
        let read = http_client.read(&mut closed).await.unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_tls_sniffing_domains_excluded_skips_domain_routing() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("tls");
        sniffing.domains_excluded = vec!["blocked.example".to_owned()];
        inbound.sniffing = Some(sniffing);
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![
                freedom_outbound_with_domain_strategy(None),
                blackhole_outbound("blocked"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", tls_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let mut tls = connector.connect("blocked.example", client).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        proxy_task.abort();
    }

    #[test]
    fn sniffed_host_exclusion_matches_routing_domain_forms() {
        for excluded in [
            "domain:blocked.example",
            "full:api.blocked.example",
            "keyword:blocked",
            r"regexp:^api\.blocked\.example$",
        ] {
            assert!(sniffed_host_is_excluded(
                &DestinationHost::Domain("api.blocked.example".to_owned()),
                &[excluded.to_owned()],
            ));
        }
        assert!(sniffed_host_is_excluded(
            &DestinationHost::Domain("baidu.com".to_owned()),
            &["geosite:cn".to_owned()],
        ));
        assert!(sniffed_host_is_excluded(
            &DestinationHost::Domain("router.asus.com".to_owned()),
            &["geosite:private".to_owned()],
        ));
    }

    #[test]
    fn sniffed_host_exclusion_does_not_match_unrelated_domains() {
        for excluded in [
            "domain:blocked.example",
            "full:blocked.example",
            "keyword:blocked",
            r"regexp:^blocked\.example$",
        ] {
            assert!(!sniffed_host_is_excluded(
                &DestinationHost::Domain("allowed.example".to_owned()),
                &[excluded.to_owned()],
            ));
        }
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_metadata_only_routes_protocol_without_host_override() {
        let (http_port, http_task) = start_http_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("http");
        sniffing.metadata_only = true;
        inbound.sniffing = Some(sniffing);
        let mut protocol_rule = blocked_example_rule();
        protocol_rule.domain.clear();
        protocol_rule.protocol = vec!["http".to_owned()];
        protocol_rule.outbound_tag = Some("direct".to_owned());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![protocol_rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut http_response = Vec::new();
        client.read_to_end(&mut http_response).await.unwrap();
        assert!(String::from_utf8_lossy(&http_response).contains("200 OK"));
        assert_eq!(http_task.await.unwrap(), "GET / HTTP/1.1");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_metadata_only_overrides_route_only_host_routing() {
        let (http_port, http_task) = start_http_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("http");
        sniffing.metadata_only = true;
        sniffing.route_only = true;
        inbound.sniffing = Some(sniffing);
        let mut protocol_rule = blocked_example_rule();
        protocol_rule.domain.clear();
        protocol_rule.protocol = vec!["http".to_owned()];
        protocol_rule.outbound_tag = Some("direct".to_owned());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule(), protocol_rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut http_response = Vec::new();
        client.read_to_end(&mut http_response).await.unwrap();
        assert!(String::from_utf8_lossy(&http_response).contains("200 OK"));
        assert_eq!(http_task.await.unwrap(), "GET / HTTP/1.1");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_http_sniffing_route_only_keeps_original_dial_target() {
        let (http_port, http_task) = start_http_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("http");
        sniffing.route_only = true;
        inbound.sniffing = Some(sniffing);
        let mut direct_rule = blocked_example_rule();
        direct_rule.outbound_tag = Some("direct".to_owned());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![direct_rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", http_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();

        let mut http_response = Vec::new();
        client.read_to_end(&mut http_response).await.unwrap();
        assert!(String::from_utf8_lossy(&http_response).contains("200 OK"));
        assert_eq!(http_task.await.unwrap(), "GET / HTTP/1.1");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_tls_sniffing_route_only_keeps_original_dial_target() {
        let tls_port = start_tls_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        let mut sniffing = sniffing_config("tls");
        sniffing.route_only = true;
        inbound.sniffing = Some(sniffing);
        let mut direct_rule = blocked_example_rule();
        direct_rule.outbound_tag = Some("direct".to_owned());
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![direct_rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", tls_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        let mut tls = connector.connect("blocked.example", client).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_tls_sniffing_relays_non_tls_payload() {
        let echo_port = start_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.sniffing = Some(sniffing_config("tls"));
        let (proxy_port, proxy_task) = start_proxy_with_outbounds(
            inbound,
            vec![blocked_example_rule()],
            vec![freedom_outbound_with_domain_strategy(None)],
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

        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut echoed = [0_u8; 4];
        timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"GET ");
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
            attrs: None,
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
    async fn use_ip_routing_uses_top_level_dns_hosts() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("direct".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_proxy_with_config_dns(
            test_inbound(InboundProtocol::Socks),
            Some("UseIP".to_owned()),
            vec![rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
            Some(serde_json::json!({"hosts":{"Mapped.Test.":"127.0.0.1"}})),
        )
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "mapped.test.", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(b"dns!").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"dns!");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn disable_fallback_stops_routing_system_resolution_after_configured_dns_miss() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let destination = Destination::tcp(DestinationHost::Domain("localhost".to_owned()), 443);
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(443_u16.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIP".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "disableFallback": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:localhost"],"expectIPs":["127.0.0.1"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_tcp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(outbound, "direct");
        timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn disable_fallback_if_match_stops_routing_system_resolution_after_filtered_miss() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 2]).await;
        let destination = Destination::tcp(DestinationHost::Domain("localhost".to_owned()), 443);
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(443_u16.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIP".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "disableFallbackIfMatch": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:localhost"],"expectIPs":["127.0.0.1"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_tcp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(outbound, "direct");
        timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn use_ipv4_routing_overrides_ipv6_configured_dns_query_strategy() {
        let (dns_port, dns_task) = start_udp_dns_a_server([127, 0, 0, 7]).await;
        let destination =
            Destination::tcp(DestinationHost::Domain("routing-ipv4.test".to_owned()), 443);
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(443_u16.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.7".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIPv4".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "queryStrategy": "UseIPv6",
                "disableFallback": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:routing-ipv4.test"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_tcp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        let question_end = skip_dns_name(&query, 12).unwrap();

        assert_eq!(&query[question_end..question_end + 2], &1_u16.to_be_bytes());
        assert_eq!(outbound, "blocked");
    }

    #[tokio::test]
    async fn use_ipv6_routing_queries_configured_dns_for_aaaa_records() {
        let expected_ip = "2001:db8::7".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_aaaa_server(expected_ip).await;
        let destination =
            Destination::tcp(DestinationHost::Domain("routing-ipv6.test".to_owned()), 443);
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(443_u16.into()),
            domain: Vec::new(),
            ip: vec!["2001:db8::7".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIPv6".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "disableFallback": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:routing-ipv6.test"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_tcp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        let question_end = skip_dns_name(&query, 12).unwrap();

        assert_eq!(
            &query[question_end..question_end + 2],
            &28_u16.to_be_bytes()
        );
        assert_eq!(outbound, "blocked");
    }

    #[tokio::test]
    async fn use_ipv6_udp_routing_queries_configured_dns_for_aaaa_records() {
        let expected_ip = "2001:db8::8".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_aaaa_server(expected_ip).await;
        let destination = Destination {
            host: DestinationHost::Domain("routing-udp-ipv6.test".to_owned()),
            port: 53,
            network: Network::Udp,
        };
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(53_u16.into()),
            domain: Vec::new(),
            ip: vec!["2001:db8::8".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: Some("udp".to_owned().into()),
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIPv6".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "disableFallback": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:routing-udp-ipv6.test"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_udp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();
        let query = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        let question_end = skip_dns_name(&query, 12).unwrap();

        assert_eq!(
            &query[question_end..question_end + 2],
            &28_u16.to_be_bytes()
        );
        assert_eq!(outbound, "blocked");
    }

    #[tokio::test]
    async fn use_ipv4v6_routing_queries_configured_dns_for_aaaa_after_a_miss() {
        let expected_ip = "2001:db8::9".parse().unwrap();
        let (dns_port, dns_task) = start_udp_dns_fallback_server(28, expected_ip).await;
        let destination = Destination::tcp(
            DestinationHost::Domain("routing-ipv4v6.test".to_owned()),
            443,
        );
        let session = SessionContext::new("test-in", destination.clone());
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(443_u16.into()),
            domain: Vec::new(),
            ip: vec!["2001:db8::9".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let config = RootConfig {
            outbounds: vec![
                freedom_outbound_with_tag("direct"),
                blackhole_outbound("blocked"),
            ],
            routing: xrs_config::RoutingConfig {
                rules: vec![rule],
                balancers: Vec::new(),
                domain_strategy: Some("UseIPv4v6".to_owned()),
                domain_matcher: None,
                extra: Default::default(),
            },
            dns: Some(serde_json::json!({
                "disableFallback": true,
                "servers": [{"address":"127.0.0.1","port":dns_port,"domains":["domain:routing-ipv4v6.test"]}]
            })),
            ..RootConfig::default()
        };
        let router = Router::from_config(&config).unwrap();
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));

        let outbound = pick_tcp_outbound(&router, &session, &destination, &dns_hosts)
            .await
            .unwrap();

        assert_eq!(outbound, "blocked");
        let queries = timeout(Duration::from_millis(200), dns_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dns_question_record_type(&queries[0]), 1);
        assert_eq!(dns_question_record_type(&queries[1]), 28);
    }

    #[tokio::test]
    async fn use_ipv4_ignores_ipv6_only_ip_rules() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy_with_domain_strategy(
            InboundProtocol::Socks,
            Some("UseIPv4".to_owned()),
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

        client.write_all(b"ipv4").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ipv4");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn use_ipv6_applies_ipv6_ip_rules() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy_with_domain_strategy(
            InboundProtocol::Socks,
            Some("UseIPv6".to_owned()),
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
        let read = timeout(Duration::from_millis(100), client.read(&mut closed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn use_ipv4v6_falls_back_to_ipv6_rules() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["::1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("direct".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_proxy_with_domain_strategy_and_outbounds(
            test_inbound(InboundProtocol::Socks),
            Some("UseIPv4v6".to_owned()),
            vec![rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
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

        client.write_all(b"v4v6").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"v4v6");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn use_ipv6v4_falls_back_to_ipv4_rules() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: vec!["127.0.0.1".to_owned()],
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("direct".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_proxy_with_domain_strategy_and_outbounds(
            test_inbound(InboundProtocol::Socks),
            Some("UseIPv6v4".to_owned()),
            vec![rule],
            vec![
                blackhole_outbound("blocked"),
                freedom_outbound_with_tag("direct"),
            ],
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

        client.write_all(b"v6v4").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"v6v4");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn dual_family_strategy_ignores_non_ip_rules_when_resolved() {
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
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy_with_domain_strategy(
            InboundProtocol::Socks,
            Some("UseIPv4v6".to_owned()),
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

        client.write_all(b"skip").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"skip");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn ip_on_demand_preserves_ip_rule_priority_over_domain_rules() {
        let echo_port = start_echo_server().await;
        let ip_rule = xrs_config::RoutingRuleConfig {
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
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let domain_rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: vec!["localhost".to_owned()],
            ip: Vec::new(),
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("direct".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let (proxy_port, proxy_task) = start_test_proxy_with_domain_strategy(
            InboundProtocol::Socks,
            Some("IPOnDemand".to_owned()),
            vec![ip_rule, domain_rule],
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
            attrs: None,
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
    async fn inbound_proxy_protocol_source_ip_drives_routing() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"PROXY TCP4 203.0.113.7 198.51.100.8 42300 1080\r\n")
            .await
            .unwrap();
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
    async fn inbound_raw_proxy_protocol_source_ip_drives_routing() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(raw_proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"PROXY TCP4 203.0.113.7 198.51.100.8 42300 1080\r\n")
            .await
            .unwrap();
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
    async fn inbound_proxy_protocol_v2_source_ip_drives_routing() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        let header = proxy_protocol_v2_header(
            "203.0.113.7:42300".parse().unwrap(),
            "198.51.100.8:1080".parse().unwrap(),
        );
        client.write_all(&header).await.unwrap();
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
    async fn inbound_proxy_protocol_v1_unknown_preserves_peer_source() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client.write_all(b"PROXY UNKNOWN\r\n").await.unwrap();
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
    async fn inbound_proxy_protocol_v2_unspec_preserves_peer_source() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"\r\n\r\n\0\r\nQUIT\n\x21\x00\x00\x00")
            .await
            .unwrap();
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
    async fn inbound_proxy_protocol_v2_local_preserves_peer_source() {
        let echo_port = start_echo_server().await;
        let rule = xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: Some(echo_port.into()),
            domain: Vec::new(),
            ip: Vec::new(),
            source: vec!["203.0.113.7".to_owned()],
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, vec![rule]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"\r\n\r\n\0\r\nQUIT\n\x20\x00\x00\x00")
            .await
            .unwrap();
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
    async fn inbound_proxy_protocol_slow_client_does_not_block_accept_loop() {
        let echo_port = start_echo_server().await;
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(proxy_protocol_stream_settings());
        let (proxy_port, proxy_task) = start_proxy(inbound, Vec::new()).await;
        let _slow_client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        client
            .write_all(b"PROXY TCP4 203.0.113.7 198.51.100.8 42300 1080\r\n")
            .await
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(&mut client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        proxy_task.abort();
    }

    #[test]
    fn policy_system_stats_flags_disable_runtime_counters() {
        let runtime = runtime_with_policy_system(serde_json::json!({
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }));

        runtime.counters.add_uplink(7);
        runtime.counters.add_downlink(9);

        assert_eq!(runtime.counters.snapshot(), Default::default());
    }

    #[test]
    fn policy_system_stats_flags_only_enable_requested_direction() {
        let runtime = runtime_with_policy_system(serde_json::json!({
            "statsInboundUplink": true
        }));

        runtime.counters.add_uplink(7);
        runtime.counters.add_downlink(9);

        assert_eq!(
            runtime.counters.snapshot(),
            xrs_observability::TrafficSnapshot {
                uplink: 7,
                downlink: 0
            }
        );
    }

    #[tokio::test]
    async fn policy_level_zero_handshake_timeout_closes_idle_socks_handshake() {
        let inbound = test_inbound(InboundProtocol::Socks);
        let (inbound, listener) = bind_inbound(inbound).await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds: vec![freedom_outbound_with_tag("direct")],
            policy: Some(serde_json::json!({"levels":{"0":{"handshake":0}},"system":{}})),
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
        let handshake_timeout = policy_handshake_timeout(config.policy.as_ref());
        let proxy_task = tokio::spawn(async move {
            run_inbound(
                inbound,
                listener,
                RuntimeState {
                    router,
                    outbounds,
                    dns_hosts: Arc::new(parse_runtime_dns(config.dns.as_ref())),
                    counters: Arc::new(TrafficCounters::default()),
                    vmess_replay: Arc::new(VmessReplayCache::default()),
                    handshake_timeout,
                },
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

        let mut closed = [0_u8; 1];
        let read = timeout(Duration::from_millis(200), client.read(&mut closed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        proxy_task.abort();
    }

    #[test]
    fn proxy_protocol_rejects_malformed_destination_fields() {
        assert!(parse_proxy_v1_source(b"PROXY TCP4 203.0.113.7 not-an-ip 42300 1080\r\n").is_err());
        assert!(
            parse_proxy_v1_source(b"PROXY TCP4 203.0.113.7 198.51.100.8 42300 nope\r\n").is_err()
        );
        assert!(
            parse_proxy_v1_source(b"PROXY TCP4 203.0.113.7 2001:db8::1 42300 1080\r\n").is_err()
        );
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
            attrs: None,
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
            attrs: None,
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
            attrs: None,
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
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n"
        );
        proxy_task.abort();
    }

    #[test]
    fn dokodemo_door_udp_network_targets_udp_destination() {
        for network in ["udp", "tcp,udp", "tcp, udp"] {
            let inbound = dokodemo_inbound("127.0.0.1", 53, Some(network));
            let destination = dokodemo_destination(&inbound).unwrap();

            assert_eq!(destination.network, Network::Udp);
        }
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
    async fn dokodemo_door_inbound_bridges_dns_outbound_to_ipv6_udp() {
        let (dns_port, dns_task) =
            start_udp_dns_server_on("::1", vec![0x12, 0x34, 0x81, 0x80]).await;
        let (proxy_port, proxy_task) = start_dns_proxy_with_server("::1", dns_port).await;
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
        let (proxy_port, proxy_task, echo_port) = start_tls_socks_inbound(Vec::new()).await;
        let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut client = connect_tls_client(tcp, &[]).await;

        assert_tls_socks_echo(&mut client, echo_port).await;
        proxy_task.abort();
    }

    #[tokio::test]
    async fn tls_socks_inbound_accepts_server_name_setting() {
        let (proxy_port, proxy_task, echo_port) =
            start_tls_socks_inbound_with_server_name(Some("example.com".to_owned()), Vec::new())
                .await;
        let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut client = connect_tls_client(tcp, &[]).await;

        assert_tls_socks_echo(&mut client, echo_port).await;
        proxy_task.abort();
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[tokio::test]
    async fn tls_socks_inbound_negotiates_alpn() {
        let (proxy_port, proxy_task, echo_port) =
            start_tls_socks_inbound(vec!["h2".to_owned(), "http/1.1".to_owned()]).await;
        let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let mut client = connect_tls_client(tcp, &["h2", "http/1.1"]).await;

        assert_eq!(
            client.get_ref().negotiated_alpn().unwrap(),
            Some(b"h2".to_vec())
        );
        assert_tls_socks_echo(&mut client, echo_port).await;
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
            level: None,
            email: None,
            flow: None,
            alter_id: None,
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

    #[tokio::test]
    async fn times_out_vless_upstream_that_stalls_after_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let echo_port = start_echo_server().await;
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let (proxy_port, proxy_task) = start_proxy_with_outbound(
            test_inbound(InboundProtocol::Socks),
            vless_outbound("upstream", upstream_port, id),
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
        write_trojan_command(stream, password, 0x01, host, port).await;
    }

    async fn write_trojan_command<S>(
        stream: &mut S,
        password: &str,
        command: u8,
        host: &str,
        port: u16,
    ) where
        S: AsyncWrite + Unpin,
    {
        stream
            .write_all(&trojan_password_hash(password))
            .await
            .unwrap();
        stream.write_all(b"\r\n").await.unwrap();
        stream.write_all(&[command, 0x03]).await.unwrap();
        stream.write_all(&[host.len() as u8]).await.unwrap();
        stream.write_all(host.as_bytes()).await.unwrap();
        stream.write_all(&port.to_be_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
    }

    async fn write_vless_connect<S>(stream: &mut S, id: &str, host: &str, port: u16)
    where
        S: AsyncWrite + Unpin,
    {
        write_vless_command(stream, id, 0x01, host, port).await;
    }

    async fn write_vless_command<S>(stream: &mut S, id: &str, command: u8, host: &str, port: u16)
    where
        S: AsyncWrite + Unpin,
    {
        let id = Uuid::parse_str(id).unwrap();
        stream.write_all(&[0]).await.unwrap();
        stream.write_all(id.as_bytes()).await.unwrap();
        stream.write_all(&[0, command]).await.unwrap();
        stream.write_all(&port.to_be_bytes()).await.unwrap();
        stream.write_all(&[0x02, host.len() as u8]).await.unwrap();
        stream.write_all(host.as_bytes()).await.unwrap();
    }

    async fn write_vless_udp_packet<S>(stream: &mut S, payload: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let length = u16::try_from(payload.len()).unwrap();
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        stream.write_all(payload).await.unwrap();
    }

    async fn read_vless_udp_packet<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    }

    async fn write_trojan_udp_packet<S>(stream: &mut S, host: &str, port: u16, payload: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        stream.write_all(&[0x03, host.len() as u8]).await.unwrap();
        stream.write_all(host.as_bytes()).await.unwrap();
        stream.write_all(&port.to_be_bytes()).await.unwrap();
        let length = u16::try_from(payload.len()).unwrap();
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
        stream.write_all(payload).await.unwrap();
    }

    async fn read_trojan_udp_packet<S>(stream: &mut S) -> (Destination, Vec<u8>)
    where
        S: AsyncRead + Unpin,
    {
        let mut address_type = [0_u8; 1];
        stream.read_exact(&mut address_type).await.unwrap();
        let host = match address_type[0] {
            0x01 => {
                let mut octets = [0_u8; 4];
                stream.read_exact(&mut octets).await.unwrap();
                DestinationHost::Ip(octets.into())
            }
            0x03 => {
                let mut host_len = [0_u8; 1];
                stream.read_exact(&mut host_len).await.unwrap();
                let mut host = vec![0_u8; usize::from(host_len[0])];
                stream.read_exact(&mut host).await.unwrap();
                DestinationHost::parse(&String::from_utf8(host).unwrap()).unwrap()
            }
            0x04 => {
                let mut octets = [0_u8; 16];
                stream.read_exact(&mut octets).await.unwrap();
                DestinationHost::Ip(octets.into())
            }
            other => panic!("unexpected Trojan UDP address type {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut payload).await.unwrap();
        (
            Destination {
                host,
                port: u16::from_be_bytes(port),
                network: Network::Udp,
            },
            payload,
        )
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
        start_shadowsocks_udp_proxy_with_outbounds(
            password,
            Vec::new(),
            vec![freedom_outbound_with_domain_strategy(None)],
        )
        .await
    }

    async fn start_shadowsocks_udp_proxy_with_outbounds(
        password: &str,
        rules: Vec<xrs_config::RoutingRuleConfig>,
        outbounds: Vec<OutboundConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let inbound = shadowsocks_udp_inbound(password);
        let socket = bind_udp_inbound(&inbound).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let config = RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound.clone()],
            outbounds,
            routing: xrs_config::RoutingConfig {
                rules,
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
                extra: Default::default(),
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
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));
        let counters = Arc::new(TrafficCounters::default());
        let task = tokio::spawn(async move {
            run_shadowsocks_udp_inbound(inbound, socket, router, outbounds, dns_hosts, counters)
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
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: Some(SHADOWSOCKS_METHOD.to_owned()),
                password: Some(password.to_owned()),
                network: Some(network.to_owned()),
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
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
                    email: None,
                    level: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: None,
                password: None,
                network: Some("tcp".to_owned()),
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
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

    fn vmess_outbound_with_security(
        tag: &str,
        port: u16,
        id: &str,
        security: &str,
    ) -> OutboundConfig {
        let mut outbound = vmess_outbound_with_tls(tag, port, id, false);
        outbound.stream_settings = None;
        outbound
            .settings
            .as_mut()
            .unwrap()
            .servers
            .first_mut()
            .unwrap()
            .security = Some(security.to_owned());
        outbound
    }

    fn vmess_outbound_with_tls(tag: &str, port: u16, id: &str, use_tls: bool) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Vmess,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: None,
                    password: None,
                    id: Some(id.to_owned()),
                    security: Some("none".to_owned()),
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
            extra: Default::default(),
        }
    }

    fn vless_outbound(tag: &str, port: u16, id: &str) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Vless,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: None,
                    password: None,
                    id: Some(id.to_owned()),
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        }
    }

    fn trojan_outbound(tag: &str, port: u16, password: &str) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Trojan,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: None,
                    password: Some(password.to_owned()),
                    id: None,
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        }
    }

    fn shadowsocks_outbound(tag: &str, port: u16, password: &str) -> OutboundConfig {
        shadowsocks_outbound_with_address(tag, "127.0.0.1", port, password)
    }

    fn shadowsocks_outbound_with_address(
        tag: &str,
        address: &str,
        port: u16,
        password: &str,
    ) -> OutboundConfig {
        let mut outbound = shadowsocks_outbound_with_tls(tag, port, password, false);
        outbound.stream_settings = None;
        if let Some(settings) = outbound.settings.as_mut() {
            settings.servers[0].address = address.to_owned();
        }
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
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: None,
                    method: Some(SHADOWSOCKS_METHOD.to_owned()),
                    password: Some(password.to_owned()),
                    id: None,
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
            extra: Default::default(),
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

    fn raw_tcp_stream_settings(network: &str) -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            network: Some(network.to_owned()),
            security: Some("none".to_owned()),
            raw_settings: Some(xrs_config::RawSettingsConfig::default()),
            tcp_settings: Some(xrs_config::RawSettingsConfig::default()),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn proxy_protocol_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            network: Some("tcp".to_owned()),
            tcp_settings: Some(xrs_config::RawSettingsConfig {
                accept_proxy_protocol: true,
                ..xrs_config::RawSettingsConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn raw_proxy_protocol_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            network: Some("raw".to_owned()),
            raw_settings: Some(xrs_config::RawSettingsConfig {
                accept_proxy_protocol: true,
                ..xrs_config::RawSettingsConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn tcp_no_delay_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_no_delay: true,
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn tcp_fast_open_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_fast_open: true,
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn tcp_keepalive_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_keep_alive_interval: Some(15),
                tcp_keep_alive_idle: Some(30),
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn zero_tcp_keepalive_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_keep_alive_interval: Some(0),
                tcp_keep_alive_idle: Some(0),
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn tcp_user_timeout_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_user_timeout: Some(1000),
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn zero_tcp_user_timeout_stream_settings() -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                tcp_user_timeout: Some(0),
                ..xrs_config::SockoptConfig::default()
            }),
            ..xrs_config::StreamSettingsConfig::default()
        }
    }

    fn sockopt_domain_strategy_stream_settings(strategy: &str) -> xrs_config::StreamSettingsConfig {
        xrs_config::StreamSettingsConfig {
            sockopt: Some(xrs_config::SockoptConfig {
                domain_strategy: Some(strategy.to_owned()),
                ..xrs_config::SockoptConfig::default()
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
        socks_outbound_with_address(tag, "127.0.0.1", port, user, password)
    }

    fn socks_outbound_with_address(
        tag: &str,
        address: &str,
        port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> OutboundConfig {
        let mut outbound = socks_outbound_with_tls(tag, port, user, password, false);
        outbound.stream_settings = None;
        if let Some(settings) = outbound.settings.as_mut() {
            settings.servers[0].address = address.to_owned();
        }
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
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port,
                    user: user.map(str::to_owned),
                    method: None,
                    password: password.map(str::to_owned),
                    id: None,
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: use_tls.then(tls_stream_settings),
            mux: None,
            extra: Default::default(),
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
                extra: Default::default(),
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
                RuntimeState {
                    router,
                    outbounds,
                    dns_hosts: Arc::new(RuntimeDns::default()),
                    counters,
                    vmess_replay: Arc::new(VmessReplayCache::default()),
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                },
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

    async fn start_vless_upstream(target_port: u16, id: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = Uuid::parse_str(id).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut version = [0_u8; 1];
            stream.read_exact(&mut version).await.unwrap();
            assert_eq!(version, [0]);
            let mut client_id = [0_u8; 16];
            stream.read_exact(&mut client_id).await.unwrap();
            assert_eq!(&client_id, id.as_bytes());
            let mut options_and_command = [0_u8; 2];
            stream.read_exact(&mut options_and_command).await.unwrap();
            assert_eq!(options_and_command, [0, 0x01]);
            let port = read_port(&mut stream).await.unwrap();
            assert_eq!(port, target_port);
            let mut address_type = [0_u8; 1];
            stream.read_exact(&mut address_type).await.unwrap();
            let _host = read_vless_host(&mut stream, address_type[0]).await.unwrap();
            stream.write_all(&[0, 0]).await.unwrap();
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            remote.write_all(&payload).await.unwrap();
            let mut response = [0_u8; 4];
            remote.read_exact(&mut response).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        port
    }

    async fn start_trojan_upstream(target_port: u16, password: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password_hash = trojan_password_hash(password);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 56];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header, password_hash);
            let mut crlf = [0_u8; 2];
            stream.read_exact(&mut crlf).await.unwrap();
            assert_eq!(&crlf, b"\r\n");
            let mut command = [0_u8; 1];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(command, [0x01]);
            let mut address_type = [0_u8; 1];
            stream.read_exact(&mut address_type).await.unwrap();
            let host = read_socks_host(&mut stream, address_type[0]).await.unwrap();
            assert_eq!(host.to_string(), "127.0.0.1");
            let port = read_port(&mut stream).await.unwrap();
            assert_eq!(port, target_port);
            stream.read_exact(&mut crlf).await.unwrap();
            assert_eq!(&crlf, b"\r\n");
            let mut remote = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            remote.write_all(&payload).await.unwrap();
            let mut response = [0_u8; 4];
            remote.read_exact(&mut response).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        port
    }

    async fn start_trojan_udp_upstream(target_port: u16, password: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password_hash = trojan_password_hash(password);
        tokio::spawn(async move {
            let mut stream =
                accept_trojan_udp_upstream_stream(listener, password_hash, target_port).await;
            let (_, payload) = read_trojan_udp_packet(&mut stream).await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&payload, ("127.0.0.1", target_port))
                .await
                .unwrap();
            let mut response = [0_u8; 65535];
            let length = socket.recv(&mut response).await.unwrap();
            write_trojan_udp_packet(&mut stream, "127.0.0.1", target_port, &response[..length])
                .await;
        });
        port
    }

    async fn start_trojan_udp_response_destination_upstream(password: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password_hash = trojan_password_hash(password);
        tokio::spawn(async move {
            let mut stream = accept_trojan_udp_upstream_stream(listener, password_hash, 53).await;
            let _ = read_trojan_udp_packet(&mut stream).await;
            write_trojan_udp_packet(&mut stream, "example.com", 5353, b"pong").await;
        });
        port
    }

    async fn start_silent_then_loud_trojan_udp_upstream(password: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password_hash = trojan_password_hash(password);
        tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            accept_trojan_udp_upstream_header(&mut first, password_hash, 53).await;
            let (_, first_payload) = read_trojan_udp_packet(&mut first).await;
            assert_eq!(&first_payload, b"silent");
            let (mut second, _) = listener.accept().await.unwrap();
            accept_trojan_udp_upstream_header(&mut second, password_hash, 53).await;
            let (_, second_payload) = read_trojan_udp_packet(&mut second).await;
            assert_eq!(&second_payload, b"loud");
            write_trojan_udp_packet(&mut second, "127.0.0.1", 53, b"pong").await;
        });
        port
    }

    async fn accept_trojan_udp_upstream_stream(
        listener: TcpListener,
        password_hash: [u8; 56],
        target_port: u16,
    ) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_trojan_udp_upstream_header(&mut stream, password_hash, target_port).await;
        stream
    }

    async fn accept_trojan_udp_upstream_header(
        stream: &mut TcpStream,
        password_hash: [u8; 56],
        target_port: u16,
    ) {
        let mut header = [0_u8; 56];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header, password_hash);
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).await.unwrap();
        assert_eq!(command, [0x03]);
        let mut address_type = [0_u8; 1];
        stream.read_exact(&mut address_type).await.unwrap();
        let host = read_socks_host(stream, address_type[0]).await.unwrap();
        assert_eq!(host.to_string(), "127.0.0.1");
        let port = read_port(stream).await.unwrap();
        assert_eq!(port, target_port);
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
    }

    async fn start_vless_udp_upstream(target_port: u16, id: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = Uuid::parse_str(id).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut version = [0_u8; 1];
            stream.read_exact(&mut version).await.unwrap();
            assert_eq!(version, [0]);
            let mut client_id = [0_u8; 16];
            stream.read_exact(&mut client_id).await.unwrap();
            assert_eq!(&client_id, id.as_bytes());
            let mut options_and_command = [0_u8; 2];
            stream.read_exact(&mut options_and_command).await.unwrap();
            assert_eq!(options_and_command, [0, 0x02]);
            let port = read_port(&mut stream).await.unwrap();
            assert_eq!(port, target_port);
            let mut address_type = [0_u8; 1];
            stream.read_exact(&mut address_type).await.unwrap();
            let host = read_vless_host(&mut stream, address_type[0]).await.unwrap();
            stream.write_all(&[0, 0]).await.unwrap();
            let payload = read_vless_udp_packet(&mut stream).await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&payload, (host.to_string(), target_port))
                .await
                .unwrap();
            let mut response = [0_u8; 65535];
            let length = socket.recv(&mut response).await.unwrap();
            write_vless_udp_packet(&mut stream, &response[..length]).await;
        });
        port
    }

    async fn start_vmess_udp_upstream(target_port: u16, id: &str) -> u16 {
        start_vmess_udp_upstream_with_tls(target_port, id, false).await
    }

    async fn start_tls_vmess_udp_upstream(target_port: u16, id: &str) -> u16 {
        start_vmess_udp_upstream_with_tls(target_port, id, true).await
    }

    async fn start_vmess_udp_upstream_with_tls(target_port: u16, id: &str, use_tls: bool) -> u16 {
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
            assert_eq!(request.destination.network, Network::Udp);
            let response_key = vmess_response_derive(&request.body_key);
            let response_iv = vmess_response_derive(&request.body_iv);
            let session = VmessSession {
                reader: VmessReader {
                    key: request.body_key,
                    iv: request.body_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
                },
                writer: VmessWriter {
                    key: response_key,
                    iv: response_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
                },
                response_auth: request.response_auth,
            };
            write_vmess_response_header(&mut stream, &session, request.response_auth)
                .await
                .unwrap();
            let payload = session
                .reader
                .clone()
                .read_chunk(&mut stream)
                .await
                .unwrap()
                .unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(
                    &payload,
                    (
                        request.destination.host.to_string(),
                        request.destination.port,
                    ),
                )
                .await
                .unwrap();
            let mut response = [0_u8; 65535];
            let length = socket.recv(&mut response).await.unwrap();
            let mut writer = session.writer;
            writer
                .write_chunk(&mut stream, &response[..length])
                .await
                .unwrap();
            writer.write_end(&mut stream).await.unwrap();
        });
        port
    }

    async fn start_unresponsive_vmess_udp_upstream(id: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = Uuid::parse_str(id).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = OutboundStream::Tcp(stream);
            let (request, _) = read_vmess_request(&mut stream, &[id], None).await.unwrap();
            assert_eq!(request.destination.network, Network::Udp);
            let response_key = vmess_response_derive(&request.body_key);
            let response_iv = vmess_response_derive(&request.body_iv);
            let session = VmessSession {
                reader: VmessReader {
                    key: request.body_key,
                    iv: request.body_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
                },
                writer: VmessWriter {
                    key: response_key,
                    iv: response_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
                },
                response_auth: request.response_auth,
            };
            write_vmess_response_header(&mut stream, &session, request.response_auth)
                .await
                .unwrap();
            let _payload = session
                .reader
                .clone()
                .read_chunk(&mut stream)
                .await
                .unwrap()
                .unwrap();
            std::future::pending::<()>().await;
        });
        port
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
            let response_key = vmess_response_derive(&request.body_key);
            let response_iv = vmess_response_derive(&request.body_iv);
            let session = VmessSession {
                reader: VmessReader {
                    key: request.body_key,
                    iv: request.body_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
                },
                writer: VmessWriter {
                    key: response_key,
                    iv: response_iv,
                    nonce: 0,
                    masked: request.options & VMESS_OPTION_CHUNK_MASKING != 0,
                    security: request.security,
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
        start_echo_server_on("127.0.0.1").await
    }

    async fn start_echo_server_on(host: &str) -> u16 {
        let listener = TcpListener::bind((host, 0)).await.unwrap();
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

    async fn start_socks_udp_test_proxy(
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(socks_udp_inbound(), rules).await
    }

    async fn start_tls_socks_inbound(alpn: Vec<String>) -> (u16, tokio::task::JoinHandle<()>, u16) {
        start_tls_socks_inbound_with_server_name(None, alpn).await
    }

    async fn start_tls_socks_inbound_with_server_name(
        server_name: Option<String>,
        alpn: Vec<String>,
    ) -> (u16, tokio::task::JoinHandle<()>, u16) {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-core-inbound-cert.pem");
        let key = dir.join("xrs-core-inbound-key.pem");
        std::fs::write(&cert, TEST_TLS_CERT).unwrap();
        std::fs::write(&key, TEST_TLS_KEY).unwrap();
        let echo_port = start_echo_server().await;
        let outbound = OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: None,
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        };
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.stream_settings = Some(xrs_config::StreamSettingsConfig {
            network: Some("tcp".to_owned()),
            security: Some("tls".to_owned()),
            tls_settings: Some(xrs_config::TlsSettingsConfig {
                server_name,
                alpn,
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
        (proxy_port, proxy_task, echo_port)
    }

    async fn connect_tls_client(
        tcp: TcpStream,
        alpn: &[&str],
    ) -> tokio_native_tls::TlsStream<TcpStream> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        if !alpn.is_empty() {
            builder.request_alpns(alpn);
        }
        let connector = tokio_native_tls::TlsConnector::from(builder.build().unwrap());
        connector.connect("localhost", tcp).await.unwrap()
    }

    async fn assert_tls_socks_echo(
        client: &mut tokio_native_tls::TlsStream<TcpStream>,
        echo_port: u16,
    ) {
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        write_socks_connect(client, "127.0.0.1", echo_port).await;
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"tls!").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tls!");
    }

    fn runtime_with_policy_system(system: serde_json::Value) -> Runtime {
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.port = 1080;
        Runtime::new(RootConfig {
            log: xrs_config::LogConfig::default(),
            inbounds: vec![inbound],
            outbounds: vec![freedom_outbound_with_tag("direct")],
            policy: Some(serde_json::json!({"levels": {}, "system": system})),
            ..RootConfig::default()
        })
        .unwrap()
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
            extra: Default::default(),
        }
    }

    fn socks_udp_inbound() -> InboundConfig {
        let mut inbound = test_inbound(InboundProtocol::Socks);
        inbound.settings = Some(xrs_config::InboundSettings {
            udp: Some(true),
            ..xrs_config::InboundSettings::default()
        });
        inbound
    }

    fn sniffing_config(dest_override: &str) -> xrs_config::SniffingConfig {
        sniffing_config_with_overrides([dest_override])
    }

    fn sniffing_config_with_overrides<const N: usize>(
        dest_override: [&str; N],
    ) -> xrs_config::SniffingConfig {
        xrs_config::SniffingConfig {
            enabled: true,
            dest_override: dest_override.into_iter().map(str::to_owned).collect(),
            domains_excluded: Vec::new(),
            metadata_only: false,
            route_only: false,
            extra: std::collections::BTreeMap::new(),
        }
    }

    fn quic_initial_packet() -> &'static [u8] {
        &[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x02, 0x01, 0x02,
        ]
    }

    fn blocked_example_rule() -> xrs_config::RoutingRuleConfig {
        xrs_config::RoutingRuleConfig {
            rule_type: None,
            inbound_tag: vec!["test-in".to_owned()],
            port: None,
            domain: vec!["blocked.example".to_owned()],
            ip: Vec::new(),
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            attrs: None,
            outbound_tag: Some("blocked".to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    fn auth_inbound(protocol: InboundProtocol, user: &str, pass: &str) -> InboundConfig {
        let mut inbound = test_inbound(protocol);
        inbound.settings = Some(xrs_config::InboundSettings {
            address: None,
            port: None,
            clients: Vec::new(),
            auth: None,
            accounts: vec![xrs_config::InboundAccountConfig {
                user: user.to_owned(),
                pass: pass.to_owned(),
                extra: std::collections::BTreeMap::new(),
            }],
            method: None,
            password: None,
            network: None,
            udp: None,
            ip: None,
            allow_transparent: None,
            timeout: None,
            user_level: None,
            decryption: None,
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
                    email: None,
                    level: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: None,
                password: None,
                network: None,
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
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
                    email: None,
                    level: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                accounts: Vec::new(),
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: None,
                password: None,
                network: None,
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
        }
    }

    async fn start_dokodemo_proxy(target_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy(dokodemo_inbound("127.0.0.1", target_port, None), Vec::new()).await
    }

    fn dokodemo_inbound(address: &str, port: u16, network: Option<&str>) -> InboundConfig {
        InboundConfig {
            tag: "test-in".to_owned(),
            listen: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            protocol: InboundProtocol::DokodemoDoor,
            settings: Some(xrs_config::InboundSettings {
                address: Some(address.to_owned()),
                port: Some(port),
                clients: Vec::new(),
                accounts: Vec::new(),
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: None,
                password: None,
                network: network.map(str::to_owned),
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
        }
    }

    async fn start_dns_proxy(dns_port: u16) -> (u16, tokio::task::JoinHandle<()>) {
        start_dns_proxy_with_server("127.0.0.1", dns_port).await
    }

    async fn start_dns_proxy_with_server(
        dns_address: &str,
        dns_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
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
                auth: None,
                udp: None,
                ip: None,
                allow_transparent: None,
                timeout: None,
                method: None,
                password: None,
                network: None,
                user_level: None,
                decryption: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            sniffing: None,
            allocate: None,
            extra: Default::default(),
        };
        let outbound = OutboundConfig {
            tag: "dns-out".to_owned(),
            protocol: OutboundProtocol::Dns,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: dns_address.to_owned(),
                    port: dns_port,
                    user: None,
                    method: None,
                    password: None,
                    id: None,
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
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
                extra: Default::default(),
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
                RuntimeState {
                    router,
                    outbounds,
                    dns_hosts: Arc::new(RuntimeDns::default()),
                    counters,
                    vmess_replay: Arc::new(VmessReplayCache::default()),
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                },
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn start_udp_dns_server(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        start_udp_dns_server_on("127.0.0.1", response).await
    }

    async fn start_tcp_dns_a_server(address: [u8; 4]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        start_tcp_dns_a_server_with_padding(address, 0).await
    }

    async fn start_oversized_tcp_dns_a_server(
        address: [u8; 4],
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        start_tcp_dns_a_server_with_padding(address, MAX_DNS_MESSAGE_SIZE).await
    }

    async fn start_length_only_tcp_dns_server(
        response_len: u16,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let length = u16::from_be_bytes(length) as usize;
            let mut query = vec![0_u8; length];
            stream.read_exact(&mut query).await.unwrap();
            stream.write_all(&response_len.to_be_bytes()).await.unwrap();
            query
        });
        (port, task)
    }

    async fn start_tcp_dns_a_server_with_padding(
        address: [u8; 4],
        padding_len: usize,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let length = u16::from_be_bytes(length) as usize;
            let mut query = vec![0_u8; length];
            stream.read_exact(&mut query).await.unwrap();
            let question_end = skip_dns_name(&query, 12).unwrap() + 4;
            let mut response = Vec::with_capacity(question_end + 16 + padding_len);
            response.extend_from_slice(&query[..2]);
            response
                .extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
            response.extend_from_slice(&query[12..question_end]);
            response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]);
            response.extend_from_slice(&address);
            response.resize(response.len() + padding_len, 0);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
            query
        });
        (port, task)
    }

    async fn start_udp_dns_a_server(address: [u8; 4]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        start_udp_dns_record_server(1, IpAddr::from(address)).await
    }

    async fn start_udp_dns_aaaa_server(address: IpAddr) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        start_udp_dns_record_server(28, address).await
    }

    async fn start_udp_dns_record_server(
        record_type: u16,
        address: IpAddr,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = buffer[..length].to_vec();
            let response = dns_response_for_query(&query, record_type, address);
            socket.send_to(&response, peer).await.unwrap();
            query
        });
        (port, task)
    }

    async fn start_udp_dns_fallback_server(
        record_type: u16,
        address: IpAddr,
    ) -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut queries = Vec::new();
            for _ in 0..2 {
                let mut buffer = [0_u8; 512];
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let query = buffer[..length].to_vec();
                let query_record_type = dns_question_record_type(&query);
                let response = if query_record_type == record_type {
                    dns_response_for_query(&query, record_type, address)
                } else {
                    dns_empty_response_for_query(&query)
                };
                socket.send_to(&response, peer).await.unwrap();
                queries.push(query);
            }
            queries
        });
        (port, task)
    }

    fn dns_question_record_type(query: &[u8]) -> u16 {
        let question_end = skip_dns_name(query, 12).unwrap();
        u16::from_be_bytes([query[question_end], query[question_end + 1]])
    }

    fn dns_response_for_query(query: &[u8], record_type: u16, address: IpAddr) -> Vec<u8> {
        let question_end = skip_dns_name(query, 12).unwrap() + 4;
        let data = match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        let mut response = Vec::with_capacity(question_end + 12 + data.len());
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[12..question_end]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
        response
    }

    fn dns_cname_response_for_query(query: &[u8], address: IpAddr) -> Vec<u8> {
        let question_end = skip_dns_name(query, 12).unwrap() + 4;
        let alias = [
            5, b'a', b'l', b'i', b'a', b's', 4, b't', b'e', b's', b't', 0,
        ];
        let data = match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[12..question_end]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&5_u16.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        response.extend_from_slice(&(alias.len() as u16).to_be_bytes());
        response.extend_from_slice(&alias);
        response.extend_from_slice(&alias);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
        response
    }

    fn dns_empty_response_for_query(query: &[u8]) -> Vec<u8> {
        let question_end = skip_dns_name(query, 12).unwrap() + 4;
        let mut response = Vec::with_capacity(question_end);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[12..question_end]);
        response
    }

    async fn start_udp_dns_server_on(
        address: &str,
        response: Vec<u8>,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let socket = UdpSocket::bind((address, 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&response, peer).await.unwrap();
            buffer[..length].to_vec()
        });
        (port, task)
    }

    async fn start_stateful_udp_server() -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (first_len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let first = buffer[..first_len].to_vec();
            socket.send_to(b"ack1", peer).await.unwrap();
            let (second_len, second_peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(second_peer, peer);
            let second = buffer[..second_len].to_vec();
            socket.send_to(b"ack2", second_peer).await.unwrap();
            vec![first, second]
        });
        (port, task)
    }

    async fn start_delayed_response_udp_server() -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (first_len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let first = buffer[..first_len].to_vec();
            let (second_len, second_peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(second_peer, peer);
            let second = buffer[..second_len].to_vec();
            socket.send_to(b"ack", second_peer).await.unwrap();
            vec![first, second]
        });
        (port, task)
    }

    async fn start_shadowsocks_udp_upstream(password: &str) -> u16 {
        start_shadowsocks_udp_upstream_on("127.0.0.1", password).await
    }

    async fn start_shadowsocks_udp_upstream_on(address: &str, password: &str) -> u16 {
        let socket = UdpSocket::bind((address, 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let key = shadowsocks_password_key(password);
        let address = address.to_owned();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 65535];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let (destination, payload) =
                decrypt_shadowsocks_udp_packet(key, &buffer[..length]).unwrap();
            let upstream = UdpSocket::bind((address.as_str(), 0)).await.unwrap();
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
            extra: Default::default(),
        })
        .await
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        let outbound = OutboundConfig {
            tag: "upstream".to_owned(),
            protocol,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: vec![xrs_config::ProxyServerConfig {
                    address: "127.0.0.1".to_owned(),
                    port: upstream_port,
                    user: user.map(str::to_owned),
                    method: None,
                    password: password.map(str::to_owned),
                    id: None,
                    security: None,
                    level: None,
                    email: None,
                    flow: None,
                    alter_id: None,
                    extra: std::collections::BTreeMap::new(),
                }],
                response: None,
                redirect: None,
                domain_strategy: None,
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
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
            extra: Default::default(),
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
                extra: Default::default(),
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
                RuntimeState {
                    router,
                    outbounds,
                    dns_hosts: Arc::new(RuntimeDns::default()),
                    counters,
                    vmess_replay: Arc::new(VmessReplayCache::default()),
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                },
            )
            .await
            .unwrap();
        });
        (port, task)
    }

    async fn start_socks_udp_upstream() -> u16 {
        start_socks_udp_upstream_with_relay_host("127.0.0.1", IpAddr::from([127, 0, 0, 1])).await
    }

    async fn start_tls_socks_udp_upstream() -> u16 {
        start_socks_udp_upstream_with_tls_and_relay_host(
            "127.0.0.1",
            IpAddr::from([127, 0, 0, 1]),
            true,
        )
        .await
    }

    async fn start_socks_udp_upstream_with_unspecified_relay() -> u16 {
        start_socks_udp_upstream_with_relay_host("127.0.0.1", IpAddr::from([0, 0, 0, 0])).await
    }

    async fn start_ipv6_socks_udp_upstream_with_unspecified_relay() -> u16 {
        start_socks_udp_upstream_with_relay_host("::1", IpAddr::from([0_u16; 8])).await
    }

    async fn start_socks_udp_upstream_with_relay_host(listen: &str, relay_host: IpAddr) -> u16 {
        start_socks_udp_upstream_with_tls_and_relay_host(listen, relay_host, false).await
    }

    async fn start_socks_udp_upstream_with_tls_and_relay_host(
        listen: &str,
        relay_host: IpAddr,
        use_tls: bool,
    ) -> u16 {
        let listener = TcpListener::bind((listen, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let listen = listen.to_owned();
        let acceptor = test_tls_acceptor();
        tokio::spawn(async move {
            let (control, _) = listener.accept().await.unwrap();
            let mut control = if use_tls {
                OutboundStream::Tls(acceptor.accept(control).await.unwrap())
            } else {
                OutboundStream::Tcp(control)
            };
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).await.unwrap();
            let request = accept_socks5_request(&mut control).await;
            assert_eq!(request.network, Network::Udp);
            let relay = UdpSocket::bind((listen.as_str(), 0)).await.unwrap();
            let relay_port = relay.local_addr().unwrap().port();
            match relay_host {
                IpAddr::V4(ip) => {
                    control.write_all(&[0x05, 0x00, 0x00, 0x01]).await.unwrap();
                    control.write_all(&ip.octets()).await.unwrap();
                }
                IpAddr::V6(ip) => {
                    control.write_all(&[0x05, 0x00, 0x00, 0x04]).await.unwrap();
                    control.write_all(&ip.octets()).await.unwrap();
                }
            }
            control.write_all(&relay_port.to_be_bytes()).await.unwrap();
            let mut packet = [0_u8; 65535];
            let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
            let parsed = parse_socks_udp_packet(&packet[..length]).unwrap();
            let upstream = UdpSocket::bind((listen.as_str(), 0)).await.unwrap();
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
                    send_through: None,
                    proxy_settings: None,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    send_through: None,
                    proxy_settings: None,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
                },
            ],
        )
        .await
    }

    fn freedom_outbound_with_tag(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: None,
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        }
    }

    fn blackhole_outbound(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: tag.to_owned(),
            protocol: OutboundProtocol::Blackhole,
            send_through: None,
            proxy_settings: None,
            settings: None,
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        }
    }

    fn freedom_outbound_with_domain_strategy(domain_strategy: Option<&str>) -> OutboundConfig {
        OutboundConfig {
            tag: "direct".to_owned(),
            protocol: OutboundProtocol::Freedom,
            send_through: None,
            proxy_settings: None,
            settings: Some(xrs_config::OutboundSettings {
                servers: Vec::new(),
                response: None,
                redirect: None,
                domain_strategy: domain_strategy.map(str::to_owned),
                target_strategy: None,
                proxy_protocol: None,
                user_level: None,
                fragment: None,
                noises: None,
                final_rules: None,
                extra: std::collections::BTreeMap::new(),
            }),
            stream_settings: None,
            mux: None,
            extra: Default::default(),
        }
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
                send_through: None,
                proxy_settings: None,
                settings: Some(xrs_config::OutboundSettings {
                    servers: Vec::new(),
                    response: None,
                    redirect: Some(format!("127.0.0.1:{redirect_port}")),
                    domain_strategy: None,
                    target_strategy: None,
                    proxy_protocol: None,
                    user_level: None,
                    fragment: None,
                    noises: None,
                    final_rules: None,
                    extra: std::collections::BTreeMap::new(),
                }),
                stream_settings: None,
                mux: None,
                extra: Default::default(),
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
                    send_through: None,
                    proxy_settings: None,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    send_through: None,
                    proxy_settings: None,
                    settings: Some(xrs_config::OutboundSettings {
                        servers: Vec::new(),
                        response: Some(xrs_config::BlackholeResponseConfig {
                            kind: "http".to_owned(),
                            extra: std::collections::BTreeMap::new(),
                        }),
                        redirect: None,
                        domain_strategy: None,
                        target_strategy: None,
                        proxy_protocol: None,
                        user_level: None,
                        fragment: None,
                        noises: None,
                        final_rules: None,
                        extra: std::collections::BTreeMap::new(),
                    }),
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
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
        start_test_proxy_with_domain_strategy_inbound(
            test_inbound(protocol),
            domain_strategy,
            rules,
        )
        .await
    }

    async fn start_socks_udp_test_proxy_with_domain_strategy(
        domain_strategy: Option<String>,
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_test_proxy_with_domain_strategy_inbound(socks_udp_inbound(), domain_strategy, rules)
            .await
    }

    async fn start_test_proxy_with_domain_strategy_inbound(
        inbound: InboundConfig,
        domain_strategy: Option<String>,
        rules: Vec<xrs_config::RoutingRuleConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_domain_strategy_and_outbounds(
            inbound,
            domain_strategy,
            rules,
            vec![
                OutboundConfig {
                    tag: "direct".to_owned(),
                    protocol: OutboundProtocol::Freedom,
                    send_through: None,
                    proxy_settings: None,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
                },
                OutboundConfig {
                    tag: "blocked".to_owned(),
                    protocol: OutboundProtocol::Blackhole,
                    send_through: None,
                    proxy_settings: None,
                    settings: None,
                    stream_settings: None,
                    mux: None,
                    extra: Default::default(),
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
        start_proxy_with_config_dns(inbound, domain_strategy, rules, outbounds, None).await
    }

    async fn start_proxy_with_dns(
        dns: serde_json::Value,
        inbound: InboundConfig,
        outbounds: Vec<OutboundConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        start_proxy_with_config_dns(inbound, None, Vec::new(), outbounds, Some(dns)).await
    }

    async fn start_proxy_with_config_dns(
        inbound: InboundConfig,
        domain_strategy: Option<String>,
        rules: Vec<xrs_config::RoutingRuleConfig>,
        outbounds: Vec<OutboundConfig>,
        dns: Option<serde_json::Value>,
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
                extra: Default::default(),
            },
            dns,
            ..RootConfig::default()
        };
        let dns_hosts = Arc::new(parse_runtime_dns(config.dns.as_ref()));
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
                RuntimeState {
                    router,
                    outbounds,
                    dns_hosts,
                    counters,
                    vmess_replay: Arc::new(VmessReplayCache::default()),
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                },
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
