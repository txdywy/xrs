#![forbid(unsafe_code)]

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use xrs_common::{Destination, DestinationHost, Network};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed to read config directory {path}: {source}")]
    ReadDir {
        path: String,
        source: std::io::Error,
    },
    #[error("config directory {0} does not contain any json files")]
    EmptyConfigDir(String),
    #[error("no config files were provided")]
    EmptyConfigList,
    #[error("config must define at least one inbound")]
    MissingInbound,
    #[error("config must define at least one outbound")]
    MissingOutbound,
    #[error("inbound {tag} uses unsupported protocol {protocol}")]
    UnsupportedInbound { tag: String, protocol: String },
    #[error("outbound {tag} uses unsupported protocol {protocol}")]
    UnsupportedOutbound { tag: String, protocol: String },
    #[error("duplicate {kind} tag {tag}")]
    DuplicateTag { kind: &'static str, tag: String },
    #[error("routing rule references unknown outbound tag {0}")]
    UnknownOutboundTag(String),
    #[error("invalid routing port matcher {value}: {reason}")]
    InvalidRoutingPortMatcher { value: String, reason: String },
    #[error("invalid routing network matcher {value}: {reason}")]
    InvalidRoutingNetworkMatcher { value: String, reason: String },
    #[error("invalid routing source matcher {value}: {reason}")]
    InvalidRoutingSourceMatcher { value: String, reason: String },
    #[error("port must be between 1 and 65535")]
    InvalidPort,
    #[error("proxy outbound must define at least one server")]
    MissingProxyServer,
    #[error("dokodemo-door inbound requires valid settings.address and settings.port")]
    InvalidDokodemoSettings,
    #[error("trojan inbound requires at least one non-empty client password")]
    InvalidTrojanSettings,
    #[error("vless inbound requires at least one client with a valid UUID id")]
    InvalidVlessSettings,
    #[error("vmess requires at least one valid UUID id")]
    InvalidVmessSettings,
    #[error("shadowsocks requires method chacha20-ietf-poly1305 and non-empty password")]
    InvalidShadowsocksSettings,
    #[error("inbound proxy accounts require non-empty user and pass")]
    InvalidInboundAuthSettings,
    #[error("upstream proxy authentication requires non-empty user and pass")]
    InvalidOutboundAuthSettings,
    #[error("unsupported stream transport network {0}")]
    UnsupportedTransportNetwork(String),
    #[error("unsupported stream transport security {0}")]
    UnsupportedTransportSecurity(String),
    #[error("TLS transport settings are not supported yet")]
    UnsupportedTlsTransportFeature,
    #[error("REALITY transport settings are not supported yet")]
    UnsupportedRealityTransportFeature,
    #[error("gRPC transport settings are not supported yet")]
    UnsupportedGrpcTransportFeature,
    #[error("XHTTP transport settings are not supported yet")]
    UnsupportedXhttpTransportFeature,
    #[error("SplitHTTP transport settings are not supported yet")]
    UnsupportedSplitHttpTransportFeature,
    #[error("HTTP Upgrade transport settings are not supported yet")]
    UnsupportedHttpUpgradeTransportFeature,
    #[error("HTTP transport settings are not supported yet")]
    UnsupportedHttpTransportFeature,
    #[error("mKCP transport settings are not supported yet")]
    UnsupportedKcpTransportFeature,
    #[error("QUIC transport settings are not supported yet")]
    UnsupportedQuicTransportFeature,
    #[error("domain socket transport settings are not supported yet")]
    UnsupportedDomainSocketTransportFeature,
    #[error("WebSocket transport settings are not supported yet")]
    UnsupportedWebSocketTransportFeature,
    #[error("stream socket options are not supported yet")]
    UnsupportedSockoptFeature,
    #[error("raw TCP transport feature is not supported yet")]
    UnsupportedRawTransportFeature,
    #[error("outbound mux settings are not supported yet")]
    UnsupportedMuxFeature,
    #[error("inbound sniffing settings are not supported yet")]
    UnsupportedSniffingFeature,
    #[error("inbound allocation settings are not supported yet")]
    UnsupportedAllocationFeature,
    #[error("FakeDNS settings are not supported yet")]
    UnsupportedFakeDnsFeature,
    #[error("metrics settings are not supported yet")]
    UnsupportedMetricsFeature,
    #[error("API settings are not supported yet")]
    UnsupportedApiFeature,
    #[error("stats settings are not supported yet")]
    UnsupportedStatsFeature,
    #[error("policy settings are not supported yet")]
    UnsupportedPolicyFeature,
    #[error("observatory settings are not supported yet")]
    UnsupportedObservatoryFeature,
    #[error("burst observatory settings are not supported yet")]
    UnsupportedBurstObservatoryFeature,
    #[error("top-level DNS settings are not supported yet")]
    UnsupportedTopLevelDnsFeature,
    #[error("geodata settings are not supported yet")]
    UnsupportedGeodataFeature,
    #[error("reverse settings are not supported yet")]
    UnsupportedReverseFeature,
    #[error("top-level transport settings are not supported yet")]
    UnsupportedTopLevelTransportFeature,
    #[error("browser forwarder settings are not supported yet")]
    UnsupportedBrowserForwarderFeature,
    #[error("routing balancers are not supported yet")]
    UnsupportedRoutingBalancerFeature,
    #[error("routing domainStrategy is not supported yet")]
    UnsupportedRoutingDomainStrategyFeature,
    #[error("unsupported routing domainMatcher {0}")]
    UnsupportedRoutingDomainMatcher(String),
    #[error("routing rule field {0} is not supported yet")]
    UnsupportedRoutingRuleField(String),
    #[error("top-level field {0} is not supported yet")]
    UnsupportedTopLevelField(String),
    #[error("inbound settings field {0} is not supported yet")]
    UnsupportedInboundSettingsField(String),
    #[error("outbound settings field {0} is not supported yet")]
    UnsupportedOutboundSettingsField(String),
    #[error("inbound account field {0} is not supported yet")]
    UnsupportedInboundAccountField(String),
    #[error("inbound client field {0} is not supported yet")]
    UnsupportedInboundClientField(String),
    #[error("outbound server field {0} is not supported yet")]
    UnsupportedOutboundServerField(String),
    #[error("blackhole response field {0} is not supported yet")]
    UnsupportedBlackholeResponseField(String),
    #[error("unsupported blackhole response type {0}")]
    UnsupportedBlackholeResponseType(String),
    #[error("freedom redirect must be a valid host:port target")]
    InvalidFreedomRedirect,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RootConfig {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fakedns: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observatory: Option<Value>,
    #[serde(
        default,
        rename = "burstObservatory",
        skip_serializing_if = "Option::is_none"
    )]
    pub burst_observatory: Option<Value>,
    #[serde(
        default,
        rename = "browserForwarder",
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_forwarder: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geodata: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RootConfig {
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config = Self::parse_file(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_files(paths: &[PathBuf]) -> Result<Self, ConfigError> {
        if paths.is_empty() {
            return Err(ConfigError::EmptyConfigList);
        }
        let mut configs = paths
            .iter()
            .map(Self::parse_file)
            .collect::<Result<Vec<_>, _>>()?;
        let mut config = configs.remove(0);
        for next in configs {
            config.merge(next);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn load_dir(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut files = fs::read_dir(path)
            .map_err(|source| ConfigError::ReadDir {
                path: path.display().to_string(),
                source,
            })?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ConfigError::ReadDir {
                path: path.display().to_string(),
                source,
            })?;
        files.retain(|file| {
            file.extension()
                .is_some_and(|extension| extension == "json")
        });
        files.sort();
        if files.is_empty() {
            return Err(ConfigError::EmptyConfigDir(path.display().to_string()));
        }
        Self::load_files(&files)
    }

    fn parse_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let body = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str::<Self>(&body).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    fn merge(&mut self, next: Self) {
        self.log = next.log;
        self.inbounds.extend(next.inbounds);
        self.outbounds.extend(next.outbounds);
        self.routing.rules.extend(next.routing.rules);
        self.routing.balancers.extend(next.routing.balancers);
        self.routing.domain_strategy = next
            .routing
            .domain_strategy
            .or_else(|| self.routing.domain_strategy.take());
        self.routing.domain_matcher = next
            .routing
            .domain_matcher
            .or_else(|| self.routing.domain_matcher.take());
        self.api = next.api.or_else(|| self.api.take());
        self.dns = next.dns.or_else(|| self.dns.take());
        self.policy = next.policy.or_else(|| self.policy.take());
        self.stats = next.stats.or_else(|| self.stats.take());
        self.fakedns = next.fakedns.or_else(|| self.fakedns.take());
        self.metrics = next.metrics.or_else(|| self.metrics.take());
        self.observatory = next.observatory.or_else(|| self.observatory.take());
        self.burst_observatory = next
            .burst_observatory
            .or_else(|| self.burst_observatory.take());
        self.browser_forwarder = next
            .browser_forwarder
            .or_else(|| self.browser_forwarder.take());
        self.geodata = next.geodata.or_else(|| self.geodata.take());
        self.reverse = next.reverse.or_else(|| self.reverse.take());
        self.transport = next.transport.or_else(|| self.transport.take());
        self.version = next.version.or_else(|| self.version.take());
        for (field, value) in next.extra {
            match self.extra.get(&field) {
                Some(current) if !current.is_null() || value.is_null() => {}
                _ => {
                    self.extra.insert(field, value);
                }
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.inbounds.is_empty() {
            return Err(ConfigError::MissingInbound);
        }
        if self.outbounds.is_empty() {
            return Err(ConfigError::MissingOutbound);
        }

        let mut inbound_tags = std::collections::HashSet::new();
        for inbound in &self.inbounds {
            inbound.validate()?;
            if !inbound_tags.insert(inbound.tag.as_str()) {
                return Err(ConfigError::DuplicateTag {
                    kind: "inbound",
                    tag: inbound.tag.clone(),
                });
            }
        }

        if self.api.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedApiFeature);
        }
        if self.dns.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedTopLevelDnsFeature);
        }
        if self.policy.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedPolicyFeature);
        }
        if self.stats.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedStatsFeature);
        }
        if self.fakedns.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedFakeDnsFeature);
        }
        if self.metrics.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedMetricsFeature);
        }
        if self
            .observatory
            .as_ref()
            .is_some_and(|value| !value.is_null())
        {
            return Err(ConfigError::UnsupportedObservatoryFeature);
        }
        if self
            .burst_observatory
            .as_ref()
            .is_some_and(|value| !value.is_null())
        {
            return Err(ConfigError::UnsupportedBurstObservatoryFeature);
        }
        if self
            .browser_forwarder
            .as_ref()
            .is_some_and(|value| !value.is_null())
        {
            return Err(ConfigError::UnsupportedBrowserForwarderFeature);
        }
        if self.geodata.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedGeodataFeature);
        }
        if self.reverse.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(ConfigError::UnsupportedReverseFeature);
        }
        if self
            .transport
            .as_ref()
            .is_some_and(|value| !value.is_null())
        {
            return Err(ConfigError::UnsupportedTopLevelTransportFeature);
        }
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedTopLevelField(field));
        }

        let mut outbound_tags = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if !outbound_tags.insert(outbound.tag.as_str()) {
                return Err(ConfigError::DuplicateTag {
                    kind: "outbound",
                    tag: outbound.tag.clone(),
                });
            }
        }

        for rule in &self.routing.rules {
            if let Some(field) = rule.unsupported_field() {
                return Err(ConfigError::UnsupportedRoutingRuleField(field));
            }
            rule.validate()?;
            if let Some(outbound_tag) = &rule.outbound_tag
                && !outbound_tags.contains(outbound_tag.as_str())
            {
                return Err(ConfigError::UnknownOutboundTag(outbound_tag.clone()));
            }
        }
        if !self.routing.balancers.is_empty() {
            return Err(ConfigError::UnsupportedRoutingBalancerFeature);
        }
        if self
            .routing
            .domain_strategy
            .as_deref()
            .is_some_and(|domain_strategy| !matches!(domain_strategy, "" | "AsIs" | "IPIfNonMatch"))
        {
            return Err(ConfigError::UnsupportedRoutingDomainStrategyFeature);
        }
        if let Some(domain_matcher) = self.routing.domain_matcher.as_deref() {
            validate_routing_domain_matcher(domain_matcher)?;
        }

        Ok(())
    }

    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundConfig {
    #[serde(default = "default_inbound_tag")]
    pub tag: String,
    #[serde(default)]
    pub listen: Option<IpAddr>,
    pub port: u16,
    pub protocol: InboundProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<InboundSettings>,
    #[serde(
        default,
        rename = "streamSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocate: Option<AllocateConfig>,
}

impl InboundConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0
            || self
                .settings
                .as_ref()
                .is_some_and(|settings| settings.port == Some(0))
        {
            return Err(ConfigError::InvalidPort);
        }
        if matches!(
            self.protocol,
            InboundProtocol::Socks | InboundProtocol::Http
        ) && self
            .settings
            .as_ref()
            .is_some_and(InboundSettings::has_invalid_accounts)
        {
            return Err(ConfigError::InvalidInboundAuthSettings);
        }
        if let Some(settings) = &self.settings {
            settings.validate()?;
        }
        if self.protocol == InboundProtocol::DokodemoDoor {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::InvalidDokodemoSettings)?;
            let address = settings
                .address
                .as_deref()
                .ok_or(ConfigError::InvalidDokodemoSettings)?;
            DestinationHost::parse(address).map_err(|_| ConfigError::InvalidDokodemoSettings)?;
            settings.port.ok_or(ConfigError::InvalidDokodemoSettings)?;
        }
        if self.protocol == InboundProtocol::Trojan {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::InvalidTrojanSettings)?;
            if !settings.clients.iter().any(|client| {
                client
                    .password
                    .as_deref()
                    .is_some_and(|password| !password.is_empty())
            }) {
                return Err(ConfigError::InvalidTrojanSettings);
            }
        }
        if self.protocol == InboundProtocol::Shadowsocks {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::InvalidShadowsocksSettings)?;
            if settings.method.as_deref() != Some("chacha20-ietf-poly1305")
                || settings.password.as_deref().is_none_or(str::is_empty)
            {
                return Err(ConfigError::InvalidShadowsocksSettings);
            }
        }
        if self.protocol == InboundProtocol::Vless {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::InvalidVlessSettings)?;
            if !settings.clients.iter().any(|client| {
                client
                    .id
                    .as_deref()
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
            }) {
                return Err(ConfigError::InvalidVlessSettings);
            }
        }
        if self.protocol == InboundProtocol::Vmess {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::InvalidVmessSettings)?;
            if !settings.clients.iter().any(|client| {
                client
                    .id
                    .as_deref()
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
            }) {
                return Err(ConfigError::InvalidVmessSettings);
            }
        }
        if let Some(stream_settings) = &self.stream_settings {
            if stream_settings.security.as_deref() == Some("tls") {
                stream_settings.validate_inbound_tls()?;
            } else {
                stream_settings.validate()?;
            }
        }
        if self
            .sniffing
            .as_ref()
            .is_some_and(SniffingConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedSniffingFeature);
        }
        if self
            .allocate
            .as_ref()
            .is_some_and(AllocateConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedAllocationFeature);
        }
        Ok(())
    }
}

fn default_inbound_tag() -> String {
    "inbound".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SniffingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default,
        rename = "destOverride",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dest_override: Vec<String>,
    #[serde(
        default,
        rename = "domainsExcluded",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domains_excluded: Vec<String>,
    #[serde(default, rename = "metadataOnly")]
    pub metadata_only: bool,
    #[serde(default, rename = "routeOnly")]
    pub route_only: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl SniffingConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.enabled || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AllocateConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u64>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl AllocateConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.strategy
            .as_ref()
            .is_some_and(|strategy| !strategy.is_empty())
            || self.refresh.is_some()
            || self.concurrency.is_some()
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InboundProtocol {
    Socks,
    Http,
    #[serde(rename = "dokodemo-door")]
    DokodemoDoor,
    Trojan,
    Vless,
    Vmess,
    Shadowsocks,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InboundSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<InboundClientConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<InboundAccountConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedInboundSettingsField(field));
        }
        for account in &self.accounts {
            if let Some(field) = account.unsupported_field() {
                return Err(ConfigError::UnsupportedInboundAccountField(field));
            }
        }
        for client in &self.clients {
            if let Some(field) = client.unsupported_field() {
                return Err(ConfigError::UnsupportedInboundClientField(field));
            }
        }
        Ok(())
    }

    fn has_invalid_accounts(&self) -> bool {
        self.accounts
            .iter()
            .any(|account| account.user.is_empty() || account.pass.is_empty())
    }

    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundAccountConfig {
    pub user: String,
    pub pass: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundAccountConfig {
    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundClientConfig {
    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutboundConfig {
    #[serde(default = "default_outbound_tag")]
    pub tag: String,
    pub protocol: OutboundProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<OutboundSettings>,
    #[serde(
        default,
        rename = "streamSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxConfig>,
}

impl OutboundConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(settings) = &self.settings {
            settings.validate()?;
        }
        if matches!(
            self.protocol,
            OutboundProtocol::Dns
                | OutboundProtocol::Socks
                | OutboundProtocol::Http
                | OutboundProtocol::Shadowsocks
                | OutboundProtocol::Vmess
        ) {
            let server = self
                .settings
                .as_ref()
                .and_then(|settings| settings.servers.first())
                .ok_or(ConfigError::MissingProxyServer)?;
            if server.port == 0 {
                return Err(ConfigError::InvalidPort);
            }
            DestinationHost::parse(&server.address).map_err(|_| ConfigError::MissingProxyServer)?;
            if matches!(
                self.protocol,
                OutboundProtocol::Socks | OutboundProtocol::Http
            ) && (server.user.as_deref().is_some_and(str::is_empty)
                || server.password.as_deref().is_some_and(str::is_empty)
                || server.user.is_some() != server.password.is_some())
            {
                return Err(ConfigError::InvalidOutboundAuthSettings);
            }
            if self.protocol == OutboundProtocol::Socks
                && (server
                    .user
                    .as_deref()
                    .is_some_and(|user| user.len() > u8::MAX as usize)
                    || server
                        .password
                        .as_deref()
                        .is_some_and(|password| password.len() > u8::MAX as usize))
            {
                return Err(ConfigError::InvalidOutboundAuthSettings);
            }
            if self.protocol == OutboundProtocol::Shadowsocks
                && (server.method.as_deref() != Some("chacha20-ietf-poly1305")
                    || server.password.as_deref().is_none_or(str::is_empty))
            {
                return Err(ConfigError::InvalidShadowsocksSettings);
            }
            if self.protocol == OutboundProtocol::Vmess
                && server
                    .id
                    .as_deref()
                    .is_none_or(|id| Uuid::parse_str(id).is_err())
            {
                return Err(ConfigError::InvalidVmessSettings);
            }
        }
        if self.protocol == OutboundProtocol::Freedom
            && let Some(redirect) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.redirect.as_deref())
            && parse_host_port(redirect).is_none()
        {
            return Err(ConfigError::InvalidFreedomRedirect);
        }
        if self.protocol == OutboundProtocol::Blackhole
            && let Some(response_type) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.response.as_ref())
                .map(|response| response.kind.as_str())
            && response_type != "http"
        {
            return Err(ConfigError::UnsupportedBlackholeResponseType(
                response_type.to_owned(),
            ));
        }
        if let Some(stream_settings) = &self.stream_settings {
            stream_settings.validate()?;
            if stream_settings.security.as_deref() == Some("tls")
                && !matches!(
                    self.protocol,
                    OutboundProtocol::Freedom
                        | OutboundProtocol::Socks
                        | OutboundProtocol::Http
                        | OutboundProtocol::Shadowsocks
                        | OutboundProtocol::Vmess
                )
            {
                return Err(ConfigError::UnsupportedTlsTransportFeature);
            }
        }
        if self
            .mux
            .as_ref()
            .is_some_and(MuxConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedMuxFeature);
        }
        Ok(())
    }
}

fn default_outbound_tag() -> String {
    "direct".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundProtocol {
    Freedom,
    Blackhole,
    Dns,
    Socks,
    Http,
    Shadowsocks,
    Vmess,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MuxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default,
        rename = "concurrency",
        skip_serializing_if = "Option::is_none"
    )]
    pub concurrency: Option<i64>,
    #[serde(
        default,
        rename = "xudpConcurrency",
        skip_serializing_if = "Option::is_none"
    )]
    pub xudp_concurrency: Option<i64>,
    #[serde(default, rename = "xudpProxyUDP443")]
    pub xudp_proxy_udp443: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl MuxConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.enabled || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OutboundSettings {
    #[serde(default)]
    pub servers: Vec<ProxyServerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<BlackholeResponseConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl OutboundSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedOutboundSettingsField(field));
        }
        if let Some(response) = &self.response
            && let Some(field) = response.unsupported_field()
        {
            return Err(ConfigError::UnsupportedBlackholeResponseField(field));
        }
        for server in &self.servers {
            if let Some(field) = server.unsupported_field() {
                return Err(ConfigError::UnsupportedOutboundServerField(field));
            }
        }
        Ok(())
    }

    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlackholeResponseConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl BlackholeResponseConfig {
    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyServerConfig {
    pub address: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ProxyServerConfig {
    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StreamSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(
        default,
        rename = "tlsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_settings: Option<TlsSettingsConfig>,
    #[serde(
        default,
        rename = "realitySettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub reality_settings: Option<RealitySettingsConfig>,
    #[serde(
        default,
        rename = "rawSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub raw_settings: Option<RawSettingsConfig>,
    #[serde(
        default,
        rename = "tcpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_settings: Option<RawSettingsConfig>,
    #[serde(
        default,
        rename = "wsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub ws_settings: Option<WebSocketSettingsConfig>,
    #[serde(
        default,
        rename = "grpcSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub grpc_settings: Option<GrpcSettingsConfig>,
    #[serde(
        default,
        rename = "xhttpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub xhttp_settings: Option<XhttpSettingsConfig>,
    #[serde(
        default,
        rename = "splithttpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub split_http_settings: Option<SplitHttpSettingsConfig>,
    #[serde(
        default,
        rename = "httpupgradeSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_upgrade_settings: Option<HttpUpgradeSettingsConfig>,
    #[serde(
        default,
        rename = "httpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_settings: Option<HttpTransportSettingsConfig>,
    #[serde(
        default,
        rename = "kcpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub kcp_settings: Option<KcpSettingsConfig>,
    #[serde(
        default,
        rename = "quicSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub quic_settings: Option<QuicSettingsConfig>,
    #[serde(
        default,
        rename = "dsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_settings: Option<DomainSocketSettingsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<SockoptConfig>,
}

impl StreamSettingsConfig {
    fn validate_common(&self) -> Result<(), ConfigError> {
        if let Some(network) = &self.network
            && network != "raw"
            && network != "tcp"
        {
            return Err(ConfigError::UnsupportedTransportNetwork(network.clone()));
        }
        if self
            .raw_settings
            .as_ref()
            .is_some_and(RawSettingsConfig::has_unsupported_feature)
            || self
                .tcp_settings
                .as_ref()
                .is_some_and(RawSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedRawTransportFeature);
        }
        if self
            .reality_settings
            .as_ref()
            .is_some_and(RealitySettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedRealityTransportFeature);
        }
        if self
            .ws_settings
            .as_ref()
            .is_some_and(WebSocketSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedWebSocketTransportFeature);
        }
        if self
            .grpc_settings
            .as_ref()
            .is_some_and(GrpcSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedGrpcTransportFeature);
        }
        if self
            .xhttp_settings
            .as_ref()
            .is_some_and(XhttpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedXhttpTransportFeature);
        }
        if self
            .split_http_settings
            .as_ref()
            .is_some_and(SplitHttpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedSplitHttpTransportFeature);
        }
        if self
            .http_upgrade_settings
            .as_ref()
            .is_some_and(HttpUpgradeSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedHttpUpgradeTransportFeature);
        }
        if self
            .http_settings
            .as_ref()
            .is_some_and(HttpTransportSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedHttpTransportFeature);
        }
        if self
            .kcp_settings
            .as_ref()
            .is_some_and(KcpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedKcpTransportFeature);
        }
        if self
            .quic_settings
            .as_ref()
            .is_some_and(QuicSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedQuicTransportFeature);
        }
        if self
            .ds_settings
            .as_ref()
            .is_some_and(DomainSocketSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedDomainSocketTransportFeature);
        }
        if self
            .sockopt
            .as_ref()
            .is_some_and(SockoptConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedSockoptFeature);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.validate_common()?;
        if let Some(security) = &self.security
            && security != "none"
            && security != "tls"
        {
            return Err(ConfigError::UnsupportedTransportSecurity(security.clone()));
        }
        if self.tls_settings.as_ref().is_some_and(|settings| {
            settings.has_unsupported_outbound_feature()
                || (!settings.alpn.is_empty()
                    && (self.security.as_deref() != Some("tls") || !tls_alpn_supported()))
        }) {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        }
        Ok(())
    }

    fn validate_inbound_tls(&self) -> Result<(), ConfigError> {
        self.validate_common()?;
        let Some(tls_settings) = &self.tls_settings else {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        };
        if tls_settings.has_unsupported_inbound_feature()
            || !tls_settings.has_usable_inbound_certificate()
        {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawSettingsConfig {
    #[serde(default, rename = "acceptProxyProtocol")]
    pub accept_proxy_protocol: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
}

impl RawSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.accept_proxy_protocol || self.header.as_ref().is_some_and(|header| !header.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TlsSettingsConfig {
    #[serde(
        default,
        rename = "serverName",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_name: Option<String>,
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: bool,
    #[serde(default, rename = "alpn", skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(
        default,
        rename = "certificates",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub certificates: Vec<TlsCertificateConfig>,
    #[serde(default, rename = "disableSystemRoot")]
    pub disable_system_root: bool,
    #[serde(
        default,
        rename = "fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        rename = "pinnedPeerCertificateChainSha256",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub pinned_peer_certificate_chain_sha256: Vec<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TlsCertificateConfig {
    #[serde(
        default,
        rename = "certificateFile",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_file: Option<PathBuf>,
    #[serde(default, rename = "keyFile", skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

fn tls_alpn_supported() -> bool {
    !cfg!(any(target_os = "macos", target_os = "ios"))
}

impl TlsSettingsConfig {
    fn has_unsupported_outbound_feature(&self) -> bool {
        !self.certificates.is_empty()
            || self.disable_system_root
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.is_empty())
            || !self.pinned_peer_certificate_chain_sha256.is_empty()
            || self.extra.values().any(|value| !value.is_null())
    }

    fn has_unsupported_inbound_feature(&self) -> bool {
        self.server_name
            .as_ref()
            .is_some_and(|server_name| !server_name.is_empty())
            || self.allow_insecure
            || !self.alpn.is_empty()
            || self.disable_system_root
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.is_empty())
            || !self.pinned_peer_certificate_chain_sha256.is_empty()
            || self.extra.values().any(|value| !value.is_null())
    }

    fn has_usable_inbound_certificate(&self) -> bool {
        self.certificates.len() == 1
            && self.certificates[0].has_usable_files()
            && fs::read(self.certificates[0].certificate_file.as_ref().unwrap()).is_ok()
            && fs::read(self.certificates[0].key_file.as_ref().unwrap()).is_ok()
    }
}

impl TlsCertificateConfig {
    fn has_usable_files(&self) -> bool {
        self.certificate_file
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
            && self
                .key_file
                .as_ref()
                .is_some_and(|path| !path.as_os_str().is_empty())
            && self.extra.values().all(Value::is_null)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RealitySettingsConfig {
    #[serde(default, rename = "show")]
    pub show: bool,
    #[serde(default, rename = "dest", skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(default, rename = "serverNames", skip_serializing_if = "Vec::is_empty")]
    pub server_names: Vec<String>,
    #[serde(
        default,
        rename = "privateKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<String>,
    #[serde(default, rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, rename = "shortIds", skip_serializing_if = "Vec::is_empty")]
    pub short_ids: Vec<String>,
    #[serde(default, rename = "spiderX", skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RealitySettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.show
            || self.dest.as_ref().is_some_and(|dest| !dest.is_empty())
            || !self.server_names.is_empty()
            || self.private_key.as_ref().is_some_and(|key| !key.is_empty())
            || self.public_key.as_ref().is_some_and(|key| !key.is_empty())
            || !self.short_ids.is_empty()
            || self
                .spider_x
                .as_ref()
                .is_some_and(|spider_x| !spider_x.is_empty())
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WebSocketSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(default, rename = "acceptProxyProtocol")]
    pub accept_proxy_protocol: bool,
}

impl WebSocketSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_null())
            || self.accept_proxy_protocol
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GrpcSettingsConfig {
    #[serde(
        default,
        rename = "serviceName",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_name: Option<String>,
    #[serde(default, rename = "multiMode")]
    pub multi_mode: bool,
    #[serde(
        default,
        rename = "idle_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub idle_timeout: Option<u64>,
    #[serde(
        default,
        rename = "health_check_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub health_check_timeout: Option<u64>,
    #[serde(default, rename = "permit_without_stream")]
    pub permit_without_stream: bool,
    #[serde(
        default,
        rename = "initial_windows_size",
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_windows_size: Option<u64>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl GrpcSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.service_name
            .as_ref()
            .is_some_and(|service_name| !service_name.is_empty())
            || self.multi_mode
            || self.idle_timeout.is_some()
            || self.health_check_timeout.is_some()
            || self.permit_without_stream
            || self.initial_windows_size.is_some()
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct XhttpSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(default, rename = "extra", skip_serializing_if = "Option::is_none")]
    pub extra_config: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl XhttpSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self.mode.as_ref().is_some_and(|mode| !mode.is_empty())
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_null())
            || self
                .extra_config
                .as_ref()
                .is_some_and(|extra| !extra.is_null())
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SplitHttpSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(
        default,
        rename = "scMaxConcurrentPosts",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_max_concurrent_posts: Option<Value>,
    #[serde(
        default,
        rename = "scMaxBufferedPosts",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_max_buffered_posts: Option<Value>,
    #[serde(
        default,
        rename = "scMaxEachPostBytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_max_each_post_bytes: Option<Value>,
    #[serde(
        default,
        rename = "scMinPostsIntervalMs",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_min_posts_interval_ms: Option<Value>,
    #[serde(
        default,
        rename = "xPaddingBytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_bytes: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux: Option<Value>,
    #[serde(default, rename = "extra", skip_serializing_if = "Option::is_none")]
    pub extra_config: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl SplitHttpSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self.mode.as_ref().is_some_and(|mode| !mode.is_empty())
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_null())
            || self
                .sc_max_concurrent_posts
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self
                .sc_max_buffered_posts
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self
                .sc_max_each_post_bytes
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self
                .sc_min_posts_interval_ms
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self
                .x_padding_bytes
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self.xmux.as_ref().is_some_and(|xmux| !xmux.is_null())
            || self
                .extra_config
                .as_ref()
                .is_some_and(|extra| !extra.is_null())
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HttpUpgradeSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(default, rename = "acceptProxyProtocol")]
    pub accept_proxy_protocol: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl HttpUpgradeSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_null())
            || self.accept_proxy_protocol
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HttpTransportSettingsConfig {
    #[serde(default, rename = "host", skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(
        default,
        rename = "read_idle_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_idle_timeout: Option<u64>,
    #[serde(
        default,
        rename = "health_check_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub health_check_timeout: Option<u64>,
    #[serde(default, rename = "with_trailers")]
    pub with_trailers: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl HttpTransportSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        !self.host.is_empty()
            || self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self
                .method
                .as_ref()
                .is_some_and(|method| !method.is_empty())
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_null())
            || self.read_idle_timeout.is_some()
            || self.health_check_timeout.is_some()
            || self.with_trailers
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KcpSettingsConfig {
    #[serde(default, rename = "mtu", skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u64>,
    #[serde(default, rename = "tti", skip_serializing_if = "Option::is_none")]
    pub tti: Option<u64>,
    #[serde(
        default,
        rename = "uplinkCapacity",
        skip_serializing_if = "Option::is_none"
    )]
    pub uplink_capacity: Option<u64>,
    #[serde(
        default,
        rename = "downlinkCapacity",
        skip_serializing_if = "Option::is_none"
    )]
    pub downlink_capacity: Option<u64>,
    #[serde(default, rename = "congestion")]
    pub congestion: bool,
    #[serde(
        default,
        rename = "readBufferSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_buffer_size: Option<u64>,
    #[serde(
        default,
        rename = "writeBufferSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub write_buffer_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
    #[serde(default, rename = "seed", skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl KcpSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.mtu.is_some()
            || self.tti.is_some()
            || self.uplink_capacity.is_some()
            || self.downlink_capacity.is_some()
            || self.congestion
            || self.read_buffer_size.is_some()
            || self.write_buffer_size.is_some()
            || self.header.as_ref().is_some_and(|header| !header.is_null())
            || self.seed.as_ref().is_some_and(|seed| !seed.is_empty())
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QuicSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl QuicSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.security
            .as_ref()
            .is_some_and(|security| !security.is_empty())
            || self.key.as_ref().is_some_and(|key| !key.is_empty())
            || self.header.as_ref().is_some_and(|header| !header.is_null())
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DomainSocketSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, rename = "abstract")]
    pub abstract_namespace: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<bool>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl DomainSocketSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.abstract_namespace
            || self.padding.is_some()
            || self.extra.values().any(|value| !value.is_null())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SockoptConfig {
    #[serde(default, rename = "tcpFastOpen")]
    pub tcp_fast_open: bool,
    #[serde(
        default,
        rename = "tcpKeepAliveInterval",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive_interval: Option<u64>,
    #[serde(
        default,
        rename = "tcpKeepAliveIdle",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive_idle: Option<u64>,
    #[serde(
        default,
        rename = "tcpUserTimeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_user_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tproxy: Option<String>,
    #[serde(
        default,
        rename = "domainStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_strategy: Option<String>,
    #[serde(
        default,
        rename = "dialerProxy",
        skip_serializing_if = "Option::is_none"
    )]
    pub dialer_proxy: Option<String>,
    #[serde(default, rename = "tcpMptcp")]
    pub tcp_mptcp: bool,
    #[serde(default, rename = "interface", skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(default, rename = "tcpNoDelay")]
    pub tcp_no_delay: bool,
}

impl SockoptConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.tcp_fast_open
            || self.tcp_keep_alive_interval.is_some()
            || self.tcp_keep_alive_idle.is_some()
            || self.tcp_user_timeout.is_some()
            || self.mark.is_some()
            || self.tproxy.is_some()
            || self.domain_strategy.is_some()
            || self.dialer_proxy.is_some()
            || self.tcp_mptcp
            || self.interface_name.is_some()
            || self.tcp_no_delay
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRuleConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub balancers: Vec<Value>,
    #[serde(
        default,
        rename = "domainStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_strategy: Option<String>,
    #[serde(
        default,
        rename = "domainMatcher",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_matcher: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoutingRuleConfig {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(default, rename = "inboundTag", alias = "inbound_tag")]
    pub inbound_tag: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<RoutingPortMatcherConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_vec_or_null",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source: Vec<String>,
    #[serde(
        default,
        rename = "sourcePort",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_port: Option<RoutingPortMatcherConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<RoutingNetworkMatcherConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, rename = "outboundTag")]
    pub outbound_tag: Option<String>,
    #[serde(
        default,
        rename = "balancerTag",
        skip_serializing_if = "Option::is_none"
    )]
    pub balancer_tag: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoutingRuleConfig {
    fn unsupported_field(&self) -> Option<String> {
        self.extra
            .iter()
            .find(|(_, value)| !value.is_null())
            .map(|(field, _)| field.clone())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self
            .rule_type
            .as_deref()
            .is_some_and(|rule_type| rule_type != "field")
        {
            return Err(ConfigError::UnsupportedRoutingRuleField("type".to_owned()));
        }
        if let Some(port) = &self.port {
            port.validate()?;
        }
        if let Some(network) = &self.network {
            network.validate()?;
        }
        for source in &self.source {
            validate_routing_source_matcher(source)?;
        }
        if let Some(source_port) = &self.source_port {
            source_port.validate()?;
        }
        if !self.protocol.is_empty() {
            return Err(ConfigError::UnsupportedRoutingRuleField(
                "protocol".to_owned(),
            ));
        }
        if !self.user.is_empty() {
            return Err(ConfigError::UnsupportedRoutingRuleField("user".to_owned()));
        }
        if self.balancer_tag.is_some() {
            return Err(ConfigError::UnsupportedRoutingBalancerFeature);
        }
        if self.outbound_tag.is_none() {
            return Err(ConfigError::UnsupportedRoutingRuleField(
                "outboundTag".to_owned(),
            ));
        }
        Ok(())
    }
}

fn deserialize_string_vec_or_null<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn validate_routing_domain_matcher(value: &str) -> Result<(), ConfigError> {
    match value {
        "" | "linear" | "mph" | "hybrid" => Ok(()),
        _ => Err(ConfigError::UnsupportedRoutingDomainMatcher(
            value.to_owned(),
        )),
    }
}

fn validate_routing_source_matcher(value: &str) -> Result<(), ConfigError> {
    if value.contains('/') {
        return value.parse::<IpNet>().map(|_| ()).map_err(|source| {
            ConfigError::InvalidRoutingSourceMatcher {
                value: value.to_owned(),
                reason: source.to_string(),
            }
        });
    }

    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|source| ConfigError::InvalidRoutingSourceMatcher {
            value: value.to_owned(),
            reason: source.to_string(),
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingNetworkMatcherConfig(String);

impl RoutingNetworkMatcherConfig {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn networks(&self) -> Result<Vec<Network>, ConfigError> {
        parse_routing_networks(&self.0)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.networks().map(|_| ())
    }
}

impl From<&str> for RoutingNetworkMatcherConfig {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for RoutingNetworkMatcherConfig {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Serialize for RoutingNetworkMatcherConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RoutingNetworkMatcherConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

fn parse_routing_networks(value: &str) -> Result<Vec<Network>, ConfigError> {
    value
        .split(',')
        .map(str::trim)
        .map(parse_routing_network)
        .collect()
}

fn parse_routing_network(value: &str) -> Result<Network, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Network::Tcp),
        "udp" => Ok(Network::Udp),
        _ => Err(ConfigError::InvalidRoutingNetworkMatcher {
            value: value.to_owned(),
            reason: "expected tcp or udp".to_owned(),
        }),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPortMatcherConfig(String);

impl RoutingPortMatcherConfig {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn ranges(&self) -> Result<Vec<RoutingPortRange>, ConfigError> {
        parse_routing_port_ranges(&self.0)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.ranges().map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingPortRange {
    pub start: u16,
    pub end: u16,
}

impl RoutingPortRange {
    #[must_use]
    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl From<u16> for RoutingPortMatcherConfig {
    fn from(value: u16) -> Self {
        Self(value.to_string())
    }
}

impl From<&str> for RoutingPortMatcherConfig {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for RoutingPortMatcherConfig {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Serialize for RoutingPortMatcherConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Ok(port) = self.0.parse::<u16>() {
            serializer.serialize_u16(port)
        } else {
            serializer.serialize_str(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for RoutingPortMatcherConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => number
                .as_u64()
                .filter(|port| *port <= u16::MAX as u64)
                .map(|port| Self(port.to_string()))
                .ok_or_else(|| serde::de::Error::custom("port must be between 0 and 65535")),
            Value::String(value) => Ok(Self(value)),
            _ => Err(serde::de::Error::custom(
                "port matcher must be a number or string",
            )),
        }
    }
}

fn parse_routing_port_ranges(value: &str) -> Result<Vec<RoutingPortRange>, ConfigError> {
    value
        .split(',')
        .map(str::trim)
        .map(parse_routing_port_range)
        .collect()
}

fn parse_routing_port_range(value: &str) -> Result<RoutingPortRange, ConfigError> {
    let Some((start, end)) = value.split_once('-') else {
        let port = parse_routing_port(value)?;
        return Ok(RoutingPortRange {
            start: port,
            end: port,
        });
    };
    let start = parse_routing_port(start.trim())?;
    let end = parse_routing_port(end.trim())?;
    if start > end {
        return Err(ConfigError::InvalidRoutingPortMatcher {
            value: value.to_owned(),
            reason: "range start is greater than range end".to_owned(),
        });
    }
    Ok(RoutingPortRange { start, end })
}

fn parse_routing_port(value: &str) -> Result<u16, ConfigError> {
    let port = value
        .parse::<u16>()
        .map_err(|source| ConfigError::InvalidRoutingPortMatcher {
            value: value.to_owned(),
            reason: source.to_string(),
        })?;
    if port == 0 {
        return Err(ConfigError::InvalidRoutingPortMatcher {
            value: value.to_owned(),
            reason: "port 0 is not routable".to_owned(),
        });
    }
    Ok(port)
}

fn parse_host_port(value: &str) -> Option<(&str, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    if port == 0 || DestinationHost::parse(host).is_err() {
        return None;
    }
    Some((host, port))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FreedomTarget {
    pub address: String,
    pub port: u16,
}

impl TryFrom<FreedomTarget> for Destination {
    type Error = xrs_common::AddressError;

    fn try_from(value: FreedomTarget) -> Result<Self, Self::Error> {
        Ok(Self::tcp(
            DestinationHost::parse(&value.address)?,
            value.port,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_shadowsocks_inbound_and_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"ss-in","listen":"127.0.0.1","port":1080,"protocol":"shadowsocks","settings":{"method":"chacha20-ietf-poly1305","password":"secret","network":"tcp"}}],
          "outbounds": [{"tag":"ss-out","protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"chacha20-ietf-poly1305","password":"secret"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Shadowsocks);
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Shadowsocks);
    }

    #[test]
    fn rejects_invalid_shadowsocks_settings() {
        let invalid_method = r#"
        {
          "inbounds": [{"tag":"ss-in","listen":"127.0.0.1","port":1080,"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","password":"secret"}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(invalid_method).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidShadowsocksSettings)
        ));

        let empty_password = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"ss-out","protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"chacha20-ietf-poly1305","password":""}]}}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(empty_password).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidShadowsocksSettings)
        ));
    }

    #[test]
    fn parses_valid_vmess_inbound_and_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"vmess-in","listen":"127.0.0.1","port":1080,"protocol":"vmess","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","security":"none"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vmess);
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Vmess);
    }

    #[test]
    fn rejects_invalid_vmess_settings() {
        let invalid_inbound = r#"
        {
          "inbounds": [{"tag":"vmess-in","port":1080,"protocol":"vmess","settings":{"clients":[{"id":"not-a-uuid"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(invalid_inbound).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidVmessSettings)
        ));

        let invalid_outbound = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"not-a-uuid"}]}}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(invalid_outbound).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidVmessSettings)
        ));
    }

    #[test]
    fn parses_inert_inbound_allocation_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","allocate":{}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.inbounds[0].allocate.is_some());
    }

    #[test]
    fn rejects_unsupported_inbound_allocation_settings() {
        for allocate in [
            r#"{"strategy":"always"}"#,
            r#"{"refresh":5}"#,
            r#"{"concurrency":3}"#,
            r#"{"unknownAllocationOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","allocate":{allocate}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedAllocationFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_unknown_inbound_settings_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"unknownInboundSetting":null}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let settings = config.inbounds[0].settings.as_ref().unwrap();
        assert!(settings.extra.contains_key("unknownInboundSetting"));
    }

    #[test]
    fn rejects_unknown_inbound_settings_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"unknownInboundSetting":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundSettingsField(field))
                if field == "unknownInboundSetting"
        ));
    }

    #[test]
    fn accepts_null_unknown_inbound_account_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"accounts":[{"user":"alice","pass":"secret","unknownAccountOption":null}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let account = &config.inbounds[0].settings.as_ref().unwrap().accounts[0];
        assert!(account.extra.contains_key("unknownAccountOption"));
    }

    #[test]
    fn rejects_unknown_inbound_account_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"accounts":[{"user":"alice","pass":"secret","unknownAccountOption":true}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundAccountField(field))
                if field == "unknownAccountOption"
        ));
    }

    #[test]
    fn accepts_null_unknown_inbound_client_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret","unknownClientOption":null}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let client = &config.inbounds[0].settings.as_ref().unwrap().clients[0];
        assert!(client.extra.contains_key("unknownClientOption"));
    }

    #[test]
    fn rejects_unknown_inbound_client_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret","unknownClientOption":true}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundClientField(field))
                if field == "unknownClientOption"
        ));
    }

    #[test]
    fn accepts_null_api_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "api": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.api.is_none());
    }

    #[test]
    fn rejects_unsupported_api_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "api": {"services": ["StatsService"]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedApiFeature)
        ));
    }

    #[test]
    fn accepts_null_browser_forwarder_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "browserForwarder": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.browser_forwarder.is_none());
    }

    #[test]
    fn rejects_unsupported_browser_forwarder_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "browserForwarder": {"listenAddr": "127.0.0.1", "listenPort": 8080}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedBrowserForwarderFeature)
        ));
    }

    #[test]
    fn accepts_null_top_level_transport_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "transport": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.transport.is_none());
    }

    #[test]
    fn rejects_unsupported_top_level_transport_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "transport": {"tcpSettings": {"header": {"type": "http"}}}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTopLevelTransportFeature)
        ));
    }

    #[test]
    fn accepts_null_reverse_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "reverse": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.reverse.is_none());
    }

    #[test]
    fn rejects_unsupported_reverse_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "reverse": {"bridges": [{"tag": "bridge", "domain": "example.com"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedReverseFeature)
        ));
    }

    #[test]
    fn accepts_null_geodata_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "geodata": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.geodata.is_none());
    }

    #[test]
    fn rejects_unsupported_geodata_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "geodata": {"loader": "standard", "geoip": "geoip.dat", "geosite": "geosite.dat"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedGeodataFeature)
        ));
    }

    #[test]
    fn accepts_null_top_level_dns_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "dns": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.dns.is_none());
    }

    #[test]
    fn rejects_unsupported_top_level_dns_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "dns": {"servers": ["1.1.1.1"]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTopLevelDnsFeature)
        ));
    }

    #[test]
    fn accepts_null_policy_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "policy": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.policy.is_none());
    }

    #[test]
    fn rejects_unsupported_policy_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "policy": {"levels": {"0": {"handshake": 4}}}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedPolicyFeature)
        ));
    }

    #[test]
    fn accepts_null_stats_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "stats": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.stats.is_none());
    }

    #[test]
    fn rejects_unsupported_stats_settings() {
        for stats in [r#"{}"#, r#"{"inboundUplink":true}"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "stats": {stats}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedStatsFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_observatory_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "observatory": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.observatory.is_none());
    }

    #[test]
    fn rejects_unsupported_observatory_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "observatory": {"subjectSelector": ["proxy"], "probeURL": "https://example.com/generate_204"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedObservatoryFeature)
        ));
    }

    #[test]
    fn accepts_null_burst_observatory_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "burstObservatory": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.burst_observatory.is_none());
    }

    #[test]
    fn rejects_unsupported_burst_observatory_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "burstObservatory": {"subjectSelector": ["proxy"], "pingConfig": {"destination": "https://example.com/generate_204"}}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedBurstObservatoryFeature)
        ));
    }

    #[test]
    fn accepts_null_fakedns_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "fakedns": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.fakedns.is_none());
    }

    #[test]
    fn rejects_unsupported_fakedns_settings() {
        for fakedns in [
            r#"{"ipPool":"198.18.0.0/15","poolSize":65535}"#,
            r#"[{"ipPool":"198.18.0.0/15","poolSize":65535}]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "fakedns": {fakedns}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedFakeDnsFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_metrics_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "metrics": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.metrics.is_none());
    }

    #[test]
    fn rejects_unsupported_metrics_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "metrics": {"tag":"metrics"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedMetricsFeature)
        ));
    }

    #[test]
    fn parses_inert_inbound_sniffing_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":false,"destOverride":["http","tls","quic"],"domainsExcluded":["example.com"],"metadataOnly":true,"routeOnly":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(!sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["http", "tls", "quic"]);
        assert_eq!(sniffing.domains_excluded, ["example.com"]);
        assert!(sniffing.metadata_only);
        assert!(sniffing.route_only);
    }

    #[test]
    fn accepts_null_unknown_inbound_sniffing_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":false,"unknownSniffingOption":null}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.extra.contains_key("unknownSniffingOption"));
    }

    #[test]
    fn rejects_unknown_inbound_sniffing_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":false,"unknownSniffingOption":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedSniffingFeature)
        ));
    }

    #[test]
    fn rejects_unsupported_inbound_sniffing_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedSniffingFeature)
        ));
    }

    #[test]
    fn parses_inert_outbound_mux_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":false,"concurrency":8,"xudpConcurrency":16,"xudpProxyUDP443":"reject"}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let mux = config.outbounds[0].mux.as_ref().unwrap();
        assert!(!mux.enabled);
        assert_eq!(mux.concurrency, Some(8));
        assert_eq!(mux.xudp_concurrency, Some(16));
        assert_eq!(mux.xudp_proxy_udp443, "reject");
    }

    #[test]
    fn accepts_null_unknown_outbound_mux_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":false,"unknownMuxOption":null}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let mux = config.outbounds[0].mux.as_ref().unwrap();
        assert!(mux.extra.contains_key("unknownMuxOption"));
    }

    #[test]
    fn rejects_unknown_outbound_mux_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":false,"unknownMuxOption":true}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedMuxFeature)
        ));
    }

    #[test]
    fn rejects_unsupported_outbound_mux_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":true}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedMuxFeature)
        ));
    }

    #[test]
    fn parses_upstream_proxy_auth_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081,"user":"alice","password":"secret"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
        assert_eq!(server.user.as_deref(), Some("alice"));
        assert_eq!(server.password.as_deref(), Some("secret"));
    }

    #[test]
    fn accepts_null_unknown_outbound_settings_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"unknownOutboundSetting":null}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let settings = config.outbounds[0].settings.as_ref().unwrap();
        assert!(settings.extra.contains_key("unknownOutboundSetting"));
    }

    #[test]
    fn rejects_unknown_outbound_settings_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"unknownOutboundSetting":true}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field))
                if field == "unknownOutboundSetting"
        ));
    }

    #[test]
    fn accepts_null_unknown_outbound_server_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081,"unknownServerOption":null}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
        assert!(server.extra.contains_key("unknownServerOption"));
    }

    #[test]
    fn rejects_unknown_outbound_server_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081,"unknownServerOption":true}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field))
                if field == "unknownServerOption"
        ));
    }

    #[test]
    fn accepts_null_unknown_blackhole_response_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"response":{"type":"http","unknownResponseOption":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let response = config.outbounds[0]
            .settings
            .as_ref()
            .unwrap()
            .response
            .as_ref()
            .unwrap();
        assert!(response.extra.contains_key("unknownResponseOption"));
    }

    #[test]
    fn rejects_unknown_blackhole_response_fields() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"response":{"type":"http","unknownResponseOption":true}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedBlackholeResponseField(field))
                if field == "unknownResponseOption"
        ));
    }

    #[test]
    fn rejects_invalid_upstream_proxy_auth_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081,"user":"alice"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidOutboundAuthSettings)
        ));
    }

    #[test]
    fn rejects_overlong_socks_upstream_auth_settings() {
        let long_user = "a".repeat(256);
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
              "outbounds": [{{"tag":"socks-out","protocol":"socks","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,"user":"{long_user}","password":"secret"}}]}}}}]
            }}"#
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidOutboundAuthSettings)
        ));
    }

    #[test]
    fn parses_raw_tcp_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"network":"raw","security":"none","rawSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"network":"tcp","tcpSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .network
                .as_deref(),
            Some("raw")
        );
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .network
                .as_deref(),
            Some("tcp")
        );
    }

    #[test]
    fn parses_inert_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .is_some()
        );
    }

    #[test]
    fn parses_inert_tls_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"tlsSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"tlsSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tls_settings
                .is_some()
        );
    }

    #[test]
    fn accepts_minimal_tls_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true,"alpn":["h2","http/1.1"]}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        if tls_alpn_supported() {
            config.validate().unwrap();
        } else {
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTlsTransportFeature)
            ));
        }
    }

    #[test]
    fn accepts_minimal_inbound_tls_stream_settings() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-cert.pem");
        let key = dir.join("xrs-config-inbound-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"certificates":[{{"certificateFile":"{}","keyFile":"{}"}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_inbound_tls_client_style_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTlsTransportFeature)
        ));
    }

    #[test]
    fn rejects_inbound_tls_with_unsupported_transport_settings() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-unsupported-cert.pem");
        let key = dir.join("xrs-config-inbound-unsupported-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","rawSettings":{{"header":{{"type":"http"}}}},"tlsSettings":{{"certificates":[{{"certificateFile":"{}","keyFile":"{}"}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRawTransportFeature)
        ));
    }

    #[test]
    fn accepts_proxy_outbound_tls_stream_settings() {
        for (protocol, server_settings) in [
            ("socks", r#""user":"user","password":"secret""#),
            ("http", r#""user":"user","password":"secret""#),
            (
                "shadowsocks",
                r#""method":"chacha20-ietf-poly1305","password":"secret""#,
            ),
            (
                "vmess",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef","security":"none""#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{{"address":"example.com","port":443,{server_settings}}}]}},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"example.com","allowInsecure":true,"alpn":["h2"]}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            if tls_alpn_supported() {
                config.validate().unwrap();
            } else {
                assert!(matches!(
                    config.validate(),
                    Err(ConfigError::UnsupportedTlsTransportFeature)
                ));
            }
        }
    }

    #[test]
    fn rejects_unsupported_outbound_tls_stream_settings() {
        for protocol in ["dns", "blackhole"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{{"address":"example.com","port":443,"method":"chacha20-ietf-poly1305","password":"secret","id":"01234567-89ab-cdef-0123-456789abcdef"}}]}},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"example.com"}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTlsTransportFeature)
            ));
        }
    }

    #[test]
    fn rejects_inert_alpn_tls_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"tlsSettings":{"alpn":["h2"]}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTlsTransportFeature)
        ));
    }

    #[test]
    fn rejects_unsupported_tls_stream_settings() {
        for tls_settings in [
            r#"{"certificates":[{"certificateFile":"cert.pem"}]}"#,
            r#"{"certificates":[{"certificateFile":"cert.pem","keyFile":"key.pem","ocspStapling":true}]}"#,
            r#"{"disableSystemRoot":true}"#,
            r#"{"fingerprint":"chrome"}"#,
            r#"{"pinnedPeerCertificateChainSha256":["abc"]}"#,
            r#"{"minVersion":"1.3"}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"tlsSettings":{tls_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTlsTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_reality_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"realitySettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"realitySettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .reality_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_reality_stream_settings() {
        for reality_settings in [
            r#"{"show":true}"#,
            r#"{"dest":"example.com:443"}"#,
            r#"{"serverNames":["example.com"]}"#,
            r#"{"privateKey":"private"}"#,
            r#"{"publicKey":"public"}"#,
            r#"{"shortIds":["abcd"]}"#,
            r#"{"spiderX":"/"}"#,
            r#"{"unknownRealityOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"realitySettings":{reality_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedRealityTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_grpc_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"grpcSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"grpcSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .grpc_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_grpc_stream_settings() {
        for grpc_settings in [
            r#"{"serviceName":"svc"}"#,
            r#"{"multiMode":true}"#,
            r#"{"idle_timeout":60}"#,
            r#"{"health_check_timeout":20}"#,
            r#"{"permit_without_stream":true}"#,
            r#"{"initial_windows_size":65535}"#,
            r#"{"unknownGrpcOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"grpcSettings":{grpc_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedGrpcTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_xhttp_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"xhttpSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"xhttpSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .xhttp_settings
                .is_some()
        );
    }

    #[test]
    fn parses_inert_split_http_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"splithttpSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"splithttpSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .split_http_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_split_http_stream_settings() {
        for split_http_settings in [
            r#"{"path":"/split"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"mode":"auto"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"scMaxConcurrentPosts":100}"#,
            r#"{"scMaxBufferedPosts":30}"#,
            r#"{"scMaxEachPostBytes":"1m"}"#,
            r#"{"scMinPostsIntervalMs":10}"#,
            r#"{"xPaddingBytes":"100-1000"}"#,
            r#"{"xmux":{"maxConcurrency":4}}"#,
            r#"{"extra":{"key":"value"}}"#,
            r#"{"unknownSplitHttpOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"splithttpSettings":{split_http_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedSplitHttpTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_http_upgrade_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"httpupgradeSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"httpupgradeSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_upgrade_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_http_upgrade_stream_settings() {
        for http_upgrade_settings in [
            r#"{"host":"example.com"}"#,
            r#"{"path":"/upgrade"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"acceptProxyProtocol":true}"#,
            r#"{"unknownHttpUpgradeOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"httpupgradeSettings":{http_upgrade_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedHttpUpgradeTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_http_transport_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"httpSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"httpSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_http_transport_stream_settings() {
        for http_settings in [
            r#"{"host":["example.com"]}"#,
            r#"{"path":"/h2"}"#,
            r#"{"method":"PUT"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"read_idle_timeout":60}"#,
            r#"{"health_check_timeout":20}"#,
            r#"{"with_trailers":true}"#,
            r#"{"unknownHttpOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"httpSettings":{http_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedHttpTransportFeature)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_xhttp_stream_settings() {
        for xhttp_settings in [
            r#"{"path":"/xhttp"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"mode":"auto"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"extra":{"key":"value"}}"#,
            r#"{"unknownXhttpOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"xhttpSettings":{xhttp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedXhttpTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_kcp_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"kcpSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"kcpSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .kcp_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_kcp_stream_settings() {
        for kcp_settings in [
            r#"{"mtu":1350}"#,
            r#"{"tti":50}"#,
            r#"{"uplinkCapacity":5}"#,
            r#"{"downlinkCapacity":20}"#,
            r#"{"congestion":true}"#,
            r#"{"readBufferSize":2}"#,
            r#"{"writeBufferSize":2}"#,
            r#"{"header":{"type":"srtp"}}"#,
            r#"{"seed":"secret"}"#,
            r#"{"unknownKcpOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"kcpSettings":{kcp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedKcpTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_quic_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"quicSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"quicSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .quic_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_quic_stream_settings() {
        for quic_settings in [
            r#"{"security":"aes-128-gcm"}"#,
            r#"{"key":"secret"}"#,
            r#"{"header":{"type":"srtp"}}"#,
            r#"{"unknownQuicOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"quicSettings":{quic_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedQuicTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_domain_socket_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"dsSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"dsSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .ds_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_domain_socket_stream_settings() {
        for ds_settings in [
            r#"{"path":"/tmp/xray.sock"}"#,
            r#"{"abstract":true}"#,
            r#"{"padding":false}"#,
            r#"{"unknownDomainSocketOption":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"dsSettings":{ds_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedDomainSocketTransportFeature)
            ));
        }
    }

    #[test]
    fn parses_inert_websocket_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"wsSettings":{}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"wsSettings":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .ws_settings
                .is_some()
        );
    }

    #[test]
    fn rejects_unsupported_websocket_stream_settings() {
        for ws_settings in [
            r#"{"path":"/ws"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"acceptProxyProtocol":true}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"wsSettings":{ws_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedWebSocketTransportFeature)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_sockopt_stream_settings() {
        for sockopt in [r#"{"tcpFastOpen":true}"#, r#"{"dialerProxy":"proxy"}"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"sockopt":{sockopt}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedSockoptFeature)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_stream_settings() {
        let unsupported_network = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","streamSettings":{"network":"ws"}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(unsupported_network).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "ws"
        ));

        let unsupported_security = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":"reality"}}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(unsupported_security).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTransportSecurity(security)) if security == "reality"
        ));

        let proxy_protocol = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","streamSettings":{"tcpSettings":{"acceptProxyProtocol":true}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(proxy_protocol).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRawTransportFeature)
        ));

        let header = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"rawSettings":{"header":{"type":"http"}}}}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(header).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRawTransportFeature)
        ));
    }

    #[test]
    fn parses_minimal_local_proxy_config() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"inbound_tag":["socks-in"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Socks);
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Freedom);
    }

    #[test]
    fn parses_proxy_outbound_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"upstream","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Socks);
        let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
        assert_eq!(server.address, "127.0.0.1");
        assert_eq!(server.port, 1081);
    }

    #[test]
    fn parses_inbound_proxy_auth_accounts() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"accounts":[{"user":"user","pass":"pass"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let account = &config.inbounds[0].settings.as_ref().unwrap().accounts[0];
        assert_eq!(account.user, "user");
        assert_eq!(account.pass, "pass");
    }

    #[test]
    fn rejects_invalid_inbound_proxy_auth_accounts() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","listen":"127.0.0.1","port":1080,"protocol":"http","settings":{"accounts":[{"user":"","pass":"pass"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidInboundAuthSettings)
        ));
    }

    #[test]
    fn parses_freedom_redirect_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:8080"}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .redirect
                .as_deref(),
            Some("127.0.0.1:8080")
        );
    }

    #[test]
    fn rejects_invalid_freedom_redirect_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:0"}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidFreedomRedirect)
        ));
    }

    #[test]
    fn parses_blackhole_http_response_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"response":{"type":"http"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .response
                .as_ref()
                .unwrap()
                .kind,
            "http"
        );
    }

    #[test]
    fn rejects_unsupported_blackhole_response_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"response":{"type":"json"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedBlackholeResponseType(kind)) if kind == "json"
        ));
    }

    #[test]
    fn parses_dns_outbound_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"dns-in","listen":"127.0.0.1","port":1080,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53}}],
          "outbounds": [{"tag":"dns-out","protocol":"dns","settings":{"servers":[{"address":"127.0.0.1","port":5353}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Dns);
        let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
        assert_eq!(server.address, "127.0.0.1");
        assert_eq!(server.port, 5353);
    }

    #[test]
    fn parses_trojan_inbound_clients() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","listen":"127.0.0.1","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Trojan);
        assert_eq!(
            config.inbounds[0].settings.as_ref().unwrap().clients[0]
                .password
                .as_deref(),
            Some("secret")
        );
    }

    #[test]
    fn parses_vless_inbound_clients() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","listen":"127.0.0.1","port":1080,"protocol":"vless","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vless);
        assert_eq!(
            config.inbounds[0].settings.as_ref().unwrap().clients[0]
                .id
                .as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
    }

    #[test]
    fn rejects_vless_without_client_id() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","port":1080,"protocol":"vless","settings":{"clients":[{}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidVlessSettings)
        ));
    }

    #[test]
    fn rejects_vless_invalid_client_id() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","port":1080,"protocol":"vless","settings":{"clients":[{"id":"not-a-uuid"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidVlessSettings)
        ));
    }

    #[test]
    fn rejects_trojan_without_clients() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidTrojanSettings)
        ));
    }

    #[test]
    fn rejects_trojan_empty_client_password() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{"clients":[{"password":""}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidTrojanSettings)
        ));
    }

    #[test]
    fn rejects_dokodemo_door_without_target_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"door","port":1080,"protocol":"dokodemo-door"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidDokodemoSettings)
        ));
    }

    #[test]
    fn rejects_dokodemo_door_invalid_target_address() {
        let json = r#"
        {
          "inbounds": [{"tag":"door","port":1080,"protocol":"dokodemo-door","settings":{"address":"","port":80}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidDokodemoSettings)
        ));
    }

    #[test]
    fn rejects_proxy_outbound_without_server() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"upstream","protocol":"http","settings":{"servers":[]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingProxyServer)
        ));
    }

    #[test]
    fn rejects_proxy_outbound_zero_server_port() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"upstream","protocol":"http","settings":{"servers":[{"address":"127.0.0.1","port":0}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
    }

    #[test]
    fn rejects_dns_outbound_zero_server_port() {
        let json = r#"
        {
          "inbounds": [{"tag":"dns-in","port":1080,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53}}],
          "outbounds": [{"tag":"dns-out","protocol":"dns","settings":{"servers":[{"address":"127.0.0.1","port":0}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
    }

    #[test]
    fn rejects_dns_outbound_invalid_server_address() {
        let json = r#"
        {
          "inbounds": [{"tag":"dns-in","port":1080,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53}}],
          "outbounds": [{"tag":"dns-out","protocol":"dns","settings":{"servers":[{"address":"","port":53}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingProxyServer)
        ));
    }

    #[test]
    fn parses_xray_top_level_sections_without_runtime_support() {
        let json = r#"
        {
          "version": {"min": "0.1.0"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingInbound)
        ));
    }

    #[test]
    fn accepts_null_unknown_top_level_fields() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "unknownRootOption": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.extra.contains_key("unknownRootOption"));
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "unknownRootOption": true
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTopLevelField(field)) if field == "unknownRootOption"
        ));
    }

    #[test]
    fn merged_unknown_top_level_fields_are_rejected() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "unknownRootOption": null
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "unknownRootOption": true
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedTopLevelField(field)) if field == "unknownRootOption"
        ));
    }

    #[test]
    fn merged_unknown_top_level_fields_cannot_be_cleared_by_null() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "unknownRootOption": true
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "unknownRootOption": null
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedTopLevelField(field)) if field == "unknownRootOption"
        ));
    }

    #[test]
    fn accepts_routing_domain_matcher_modes() {
        for mode in ["", "linear", "mph", "hybrid"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"domainMatcher": "{mode}"}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(config.routing.domain_matcher.as_deref(), Some(mode));
        }
    }

    #[test]
    fn rejects_unsupported_routing_domain_matcher() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"domainMatcher": "unknown"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingDomainMatcher(value)) if value == "unknown"
        ));
    }

    #[test]
    fn merged_routing_domain_matcher_is_preserved() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "routing":{"domainMatcher":"linear"}
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"domainMatcher":"mph"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.routing.domain_matcher.as_deref(), Some("mph"));
    }

    #[test]
    fn accepts_supported_routing_domain_strategy() {
        for domain_strategy in ["", "AsIs", "IPIfNonMatch"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"domainStrategy": "{domain_strategy}"}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.routing.domain_strategy.as_deref(),
                Some(domain_strategy)
            );
        }
    }

    #[test]
    fn rejects_unsupported_routing_domain_strategy() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"domainStrategy": "IPOnDemand"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingDomainStrategyFeature)
        ));
    }

    #[test]
    fn merged_routing_domain_strategy_is_rejected() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"domainStrategy":"IPOnDemand"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedRoutingDomainStrategyFeature)
        ));
    }

    #[test]
    fn accepts_empty_routing_balancers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": []}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.routing.balancers.is_empty());
    }

    #[test]
    fn rejects_unsupported_routing_balancers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":["direct"]}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingBalancerFeature)
        ));
    }

    #[test]
    fn merged_routing_balancers_are_rejected() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"balancers":[{"tag":"auto","selector":["direct"]}]}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedRoutingBalancerFeature)
        ));
    }

    #[test]
    fn accepts_null_routing_source() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"outboundTag":"direct","source":null}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.routing.rules[0].source.is_empty());
    }

    #[test]
    fn accepts_field_routing_rule_type() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"type":"field","outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.rules[0].rule_type.as_deref(), Some("field"));
    }

    #[test]
    fn rejects_unsupported_routing_rule_types() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"type":"selector","outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "type"
        ));
    }

    #[test]
    fn rejects_routing_rule_balancer_targets() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"balancerTag":"auto"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.routing.rules[0].balancer_tag.as_deref(),
            Some("auto")
        );
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingBalancerFeature)
        ));
    }

    #[test]
    fn rejects_routing_rule_protocol_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"protocol":["bittorrent"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.routing.rules[0].protocol,
            vec!["bittorrent".to_owned()]
        );
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "protocol"
        ));
    }

    #[test]
    fn rejects_routing_rule_user_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"user":["alice@example.com"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.routing.rules[0].user,
            vec!["alice@example.com".to_owned()]
        );
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "user"
        ));
    }

    #[test]
    fn rejects_routing_rules_without_targets() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"inboundTag":["socks-in"]}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "outboundTag"
        ));
    }

    #[test]
    fn rejects_unsupported_routing_rule_fields() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"outboundTag":"direct","attrs":"tcp"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "attrs"
        ));
    }

    #[test]
    fn accepts_routing_source_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","source":["127.0.0.1","192.0.2.0/24"]}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0].source,
            vec!["127.0.0.1".to_owned(), "192.0.2.0/24".to_owned()]
        );
    }

    #[test]
    fn rejects_invalid_routing_source_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"outboundTag":"direct","source":["not-ip"]}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRoutingSourceMatcher { value, .. }) if value == "not-ip"
        ));
    }

    #[test]
    fn accepts_routing_network_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","network":"tcp"},
            {"outboundTag":"direct","network":"tcp,udp"}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![Network::Tcp]
        );
        assert_eq!(
            config.routing.rules[1]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![Network::Tcp, Network::Udp]
        );
    }

    #[test]
    fn rejects_invalid_routing_network_matchers() {
        for network in ["", "quic", "tcp,quic"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","network":"{network}"}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingNetworkMatcher { .. })
            ));
        }
    }

    #[test]
    fn accepts_numeric_and_range_routing_port_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","port":443},
            {"outboundTag":"direct","port":"8000-8999,9443"}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0].port.as_ref().unwrap().as_str(),
            "443"
        );
        assert_eq!(
            config.routing.rules[1]
                .port
                .as_ref()
                .unwrap()
                .ranges()
                .unwrap(),
            vec![
                RoutingPortRange {
                    start: 8000,
                    end: 8999
                },
                RoutingPortRange {
                    start: 9443,
                    end: 9443
                }
            ]
        );
    }

    #[test]
    fn rejects_invalid_routing_port_matchers() {
        for port in ["", "0", "9000-8000", "80-", "abc"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","port":"{port}"}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingPortMatcher { .. })
            ));
        }
    }

    #[test]
    fn accepts_numeric_and_range_routing_source_port_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","sourcePort":443},
            {"outboundTag":"direct","sourcePort":"8000-8999,9443"}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0]
                .source_port
                .as_ref()
                .unwrap()
                .as_str(),
            "443"
        );
        assert_eq!(
            config.routing.rules[1]
                .source_port
                .as_ref()
                .unwrap()
                .ranges()
                .unwrap(),
            vec![
                RoutingPortRange {
                    start: 8000,
                    end: 8999
                },
                RoutingPortRange {
                    start: 9443,
                    end: 9443
                }
            ]
        );
    }

    #[test]
    fn rejects_invalid_routing_source_port_matchers() {
        for source_port in ["", "0", "9000-8000", "80-", "abc"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","sourcePort":"{source_port}"}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingPortMatcher { .. })
            ));
        }
    }

    #[test]
    fn rejects_unknown_route_targets() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"outboundTag":"missing"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownOutboundTag(tag)) if tag == "missing"
        ));
    }

    #[test]
    fn rejects_duplicate_outbound_tags() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [
            {"tag":"direct","protocol":"freedom"},
            {"tag":"direct","protocol":"blackhole"}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateTag { kind: "outbound", tag }) if tag == "direct"
        ));
    }

    #[test]
    fn merges_config_fragments_in_order() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "log":{"level":"warning"},
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "version":{"min":"0.1.0"}
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "log":{"level":"debug"},
              "outbounds":[{"tag":"blocked","protocol":"blackhole"}],
              "routing":{"rules":[{"inboundTag":["socks-in"],"outboundTag":"blocked"}]},
              "version":{"min":"0.2.0"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.log.level, "debug");
        assert_eq!(first.inbounds.len(), 1);
        assert_eq!(first.outbounds.len(), 2);
        assert_eq!(first.routing.rules.len(), 1);
        assert_eq!(first.version.unwrap(), serde_json::json!({"min": "0.2.0"}));
    }
}
