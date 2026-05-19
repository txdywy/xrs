#![forbid(unsafe_code)]

use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use xrs_common::{Destination, DestinationHost};

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
    #[error("{kind} tag cannot be empty")]
    EmptyTag { kind: &'static str },
    #[error("routing rule references unknown outbound tag {0}")]
    UnknownOutboundTag(String),
    #[error("routing rule references unknown inbound tag {0}")]
    UnknownInboundTag(String),
    #[error("invalid routing port matcher {value}: {reason}")]
    InvalidRoutingPortMatcher { value: String, reason: String },
    #[error("invalid routing network matcher {value}: {reason}")]
    InvalidRoutingNetworkMatcher { value: String, reason: String },
    #[error("invalid routing source matcher {value}: {reason}")]
    InvalidRoutingSourceMatcher { value: String, reason: String },
    #[error("invalid routing domain matcher {value}: {reason}")]
    InvalidRoutingRuleDomainMatcher { value: String, reason: String },
    #[error("invalid routing ip matcher {value}: {reason}")]
    InvalidRoutingRuleIpMatcher { value: String, reason: String },
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
    #[error("top-level version settings are not supported yet")]
    UnsupportedVersionFeature,
    #[error("browser forwarder settings are not supported yet")]
    UnsupportedBrowserForwarderFeature,
    #[error("routing balancers are not supported yet")]
    UnsupportedRoutingBalancerFeature,
    #[error("routing domainStrategy is not supported yet")]
    UnsupportedRoutingDomainStrategyFeature,
    #[error("unsupported routing domainMatcher {0}")]
    UnsupportedRoutingDomainMatcher(String),
    #[error("routing field {0} is not supported yet")]
    UnsupportedRoutingField(String),
    #[error("routing rule field {0} is not supported yet")]
    UnsupportedRoutingRuleField(String),
    #[error("top-level field {0} is not supported yet")]
    UnsupportedTopLevelField(String),
    #[error("log field {0} is not supported yet")]
    UnsupportedLogField(String),
    #[error("streamSettings field {0} is not supported yet")]
    UnsupportedStreamSettingsField(String),
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
    #[error("inbound TLS settings field {0} is not supported yet")]
    UnsupportedInboundTlsSettingsField(String),
    #[error("unsupported blackhole response type {0}")]
    UnsupportedBlackholeResponseType(String),
    #[error("unsupported VMess security {0}")]
    UnsupportedVmessSecurity(String),
    #[error("freedom redirect must be a valid host:port target")]
    InvalidFreedomRedirect,
    #[error("unsupported freedom domainStrategy {0}")]
    UnsupportedFreedomDomainStrategy(String),
    #[error("unsupported freedom proxyProtocol {0}")]
    UnsupportedFreedomProxyProtocol(u8),
    #[error("unsupported freedom userLevel {0}")]
    UnsupportedFreedomUserLevel(u32),
    #[error("freedom fragment settings are not supported yet")]
    UnsupportedFreedomFragment,
    #[error("freedom noises settings are not supported yet")]
    UnsupportedFreedomNoises,
    #[error("freedom finalRules settings are not supported yet")]
    UnsupportedFreedomFinalRules,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RootConfig {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default, deserialize_with = "deserialize_inbound_vec_or_null")]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default, deserialize_with = "deserialize_outbound_vec_or_null")]
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
        self.log.level = next.log.level;
        self.log.dns_log |= next.log.dns_log;
        merge_log_output(&mut self.log.access, next.log.access);
        merge_log_output(&mut self.log.error, next.log.error);
        merge_inert_extra_fields(&mut self.log.extra, next.log.extra);
        self.inbounds.extend(next.inbounds);
        self.outbounds.extend(next.outbounds);
        self.routing.rules.extend(next.routing.rules);
        self.routing.balancers.extend(next.routing.balancers);
        merge_routing_domain_strategy(
            &mut self.routing.domain_strategy,
            next.routing.domain_strategy,
        );
        merge_routing_domain_matcher(
            &mut self.routing.domain_matcher,
            next.routing.domain_matcher,
        );
        merge_inert_extra_fields(&mut self.routing.extra, next.routing.extra);
        merge_api_value(&mut self.api, next.api);
        merge_dns_value(&mut self.dns, next.dns);
        merge_policy_value(&mut self.policy, next.policy);
        merge_stats_value(&mut self.stats, next.stats);
        merge_fakedns_value(&mut self.fakedns, next.fakedns);
        merge_metrics_value(&mut self.metrics, next.metrics);
        merge_observatory_value(&mut self.observatory, next.observatory);
        merge_burst_observatory_value(&mut self.burst_observatory, next.burst_observatory);
        merge_browser_forwarder_value(&mut self.browser_forwarder, next.browser_forwarder);
        merge_geodata_value(&mut self.geodata, next.geodata);
        merge_reverse_value(&mut self.reverse, next.reverse);
        merge_transport_value(&mut self.transport, next.transport);
        merge_top_level_value(&mut self.version, next.version);
        merge_inert_extra_fields(&mut self.extra, next.extra);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = self.log.unsupported_field() {
            return Err(ConfigError::UnsupportedLogField(field));
        }
        if self.inbounds.is_empty() {
            return Err(ConfigError::MissingInbound);
        }
        if self.outbounds.is_empty() {
            return Err(ConfigError::MissingOutbound);
        }

        let mut inbound_tags = std::collections::HashSet::new();
        for inbound in &self.inbounds {
            inbound.validate()?;
            if inbound.tag.trim().is_empty() {
                return Err(ConfigError::EmptyTag { kind: "inbound" });
            }
            if !inbound_tags.insert(inbound.tag.as_str()) {
                return Err(ConfigError::DuplicateTag {
                    kind: "inbound",
                    tag: inbound.tag.clone(),
                });
            }
        }

        if self
            .api
            .as_ref()
            .is_some_and(|api| !is_inert_api_config(api))
        {
            return Err(ConfigError::UnsupportedApiFeature);
        }
        if self
            .dns
            .as_ref()
            .is_some_and(|dns| !is_inert_dns_config(dns))
        {
            return Err(ConfigError::UnsupportedTopLevelDnsFeature);
        }
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| !is_inert_policy_config(policy))
        {
            return Err(ConfigError::UnsupportedPolicyFeature);
        }
        if self
            .stats
            .as_ref()
            .is_some_and(|stats| !is_inert_stats_config(stats))
        {
            return Err(ConfigError::UnsupportedStatsFeature);
        }
        if self
            .fakedns
            .as_ref()
            .is_some_and(|fakedns| !is_inert_fakedns_config(fakedns))
        {
            return Err(ConfigError::UnsupportedFakeDnsFeature);
        }
        if self
            .metrics
            .as_ref()
            .is_some_and(|metrics| !is_inert_metrics_config(metrics))
        {
            return Err(ConfigError::UnsupportedMetricsFeature);
        }
        if self
            .observatory
            .as_ref()
            .is_some_and(|observatory| !is_inert_observatory_config(observatory))
        {
            return Err(ConfigError::UnsupportedObservatoryFeature);
        }
        if self
            .burst_observatory
            .as_ref()
            .is_some_and(|burst_observatory| !is_inert_burst_observatory_config(burst_observatory))
        {
            return Err(ConfigError::UnsupportedBurstObservatoryFeature);
        }
        if self
            .browser_forwarder
            .as_ref()
            .is_some_and(|browser_forwarder| !is_inert_browser_forwarder_config(browser_forwarder))
        {
            return Err(ConfigError::UnsupportedBrowserForwarderFeature);
        }
        if self
            .geodata
            .as_ref()
            .is_some_and(|geodata| !is_inert_geodata_config(geodata))
        {
            return Err(ConfigError::UnsupportedGeodataFeature);
        }
        if self
            .reverse
            .as_ref()
            .is_some_and(|reverse| !is_inert_reverse_config(reverse))
        {
            return Err(ConfigError::UnsupportedReverseFeature);
        }
        if self
            .transport
            .as_ref()
            .is_some_and(|transport| !is_inert_top_level_transport_config(transport))
        {
            return Err(ConfigError::UnsupportedTopLevelTransportFeature);
        }
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedTopLevelField(field));
        }

        let mut outbound_tags = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if outbound.tag.trim().is_empty() {
                return Err(ConfigError::EmptyTag { kind: "outbound" });
            }
            if !outbound_tags.insert(outbound.tag.as_str()) {
                return Err(ConfigError::DuplicateTag {
                    kind: "outbound",
                    tag: outbound.tag.clone(),
                });
            }
        }

        for outbound in &self.outbounds {
            let proxy_settings_tag = outbound
                .proxy_settings
                .as_ref()
                .and_then(|settings| settings.tag.as_deref())
                .filter(|tag| !tag.trim().is_empty());
            let dialer_proxy_tag = outbound
                .stream_settings
                .as_ref()
                .and_then(|settings| settings.sockopt.as_ref())
                .and_then(|sockopt| sockopt.dialer_proxy.as_deref())
                .filter(|tag| !tag.is_empty());
            let Some(proxy_tag) = proxy_settings_tag.or(dialer_proxy_tag) else {
                continue;
            };
            let Some(proxy_outbound) = self
                .outbounds
                .iter()
                .find(|candidate| candidate.tag == proxy_tag)
            else {
                return Err(ConfigError::UnknownOutboundTag(proxy_tag.to_owned()));
            };
            let has_unsupported_freedom_chain_setting = outbound
                .settings
                .as_ref()
                .is_some_and(|settings| settings.proxy_protocol.is_some_and(|value| value != 0));
            if outbound.protocol != OutboundProtocol::Freedom
                || has_unsupported_freedom_chain_setting
                || !matches!(
                    proxy_outbound.protocol,
                    OutboundProtocol::Socks | OutboundProtocol::Http
                )
            {
                return Err(ConfigError::UnsupportedOutboundSettingsField(
                    "proxySettings".to_owned(),
                ));
            }
        }

        if let Some(field) = self.routing.unsupported_field() {
            return Err(ConfigError::UnsupportedRoutingField(field));
        }

        let mut balancer_tags = HashSet::new();
        for balancer in &self.routing.balancers {
            if let Some(field) = balancer.unsupported_field() {
                return Err(ConfigError::UnsupportedRoutingField(field));
            }
            if balancer.tag.trim().is_empty() {
                return Err(ConfigError::EmptyTag { kind: "balancer" });
            }
            if !balancer_tags.insert(balancer.tag.as_str()) {
                return Err(ConfigError::DuplicateTag {
                    kind: "balancer",
                    tag: balancer.tag.clone(),
                });
            }
            for selector in &balancer.selector {
                if selector.trim().is_empty() {
                    return Err(ConfigError::EmptyTag { kind: "outbound" });
                }
                if !outbound_tags.iter().any(|tag| tag.starts_with(selector)) {
                    return Err(ConfigError::UnknownOutboundTag(selector.clone()));
                }
            }
            if let Some(fallback_tag) = &balancer.fallback_tag {
                if fallback_tag.trim().is_empty() {
                    return Err(ConfigError::EmptyTag { kind: "outbound" });
                }
                if !outbound_tags.contains(fallback_tag.as_str()) {
                    return Err(ConfigError::UnknownOutboundTag(fallback_tag.clone()));
                }
            }
        }

        for rule in &self.routing.rules {
            if let Some(field) = rule.unsupported_field() {
                return Err(ConfigError::UnsupportedRoutingRuleField(field));
            }
            rule.validate()?;
            for inbound_tag in &rule.inbound_tag {
                if inbound_tag.trim().is_empty() {
                    return Err(ConfigError::EmptyTag { kind: "inbound" });
                }
                if !inbound_tags.contains(inbound_tag.as_str()) {
                    return Err(ConfigError::UnknownInboundTag(inbound_tag.clone()));
                }
            }
            if let Some(outbound_tag) = &rule.outbound_tag {
                if outbound_tag.trim().is_empty() {
                    return Err(ConfigError::EmptyTag { kind: "outbound" });
                }
                if !outbound_tags.contains(outbound_tag.as_str()) {
                    return Err(ConfigError::UnknownOutboundTag(outbound_tag.clone()));
                }
            }
            if let Some(balancer_tag) = &rule.balancer_tag {
                if balancer_tag.trim().is_empty() {
                    return Err(ConfigError::EmptyTag { kind: "balancer" });
                }
                if !balancer_tags.contains(balancer_tag.as_str()) {
                    return Err(ConfigError::UnsupportedRoutingBalancerFeature);
                }
            }
        }
        if self
            .routing
            .domain_strategy
            .as_deref()
            .is_some_and(|domain_strategy| {
                !matches!(
                    domain_strategy,
                    "" | "AsIs"
                        | "IPIfNonMatch"
                        | "IPOnDemand"
                        | "UseIP"
                        | "UseIPv4"
                        | "UseIPv6"
                        | "UseIPv4v6"
                        | "UseIPv6v4"
                )
            })
        {
            return Err(ConfigError::UnsupportedRoutingDomainStrategyFeature);
        }
        if let Some(domain_matcher) = self.routing.domain_matcher.as_deref() {
            validate_routing_domain_matcher(domain_matcher)?;
        }

        Ok(())
    }

    fn unsupported_field(&self) -> Option<String> {
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(
        default = "default_log_level",
        deserialize_with = "deserialize_log_level_or_null"
    )]
    pub level: String,
    #[serde(
        default,
        rename = "dnsLog",
        skip_serializing_if = "is_false",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub dns_log: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl LogConfig {
    fn unsupported_field(&self) -> Option<String> {
        if self.dns_log {
            return Some("dnsLog".to_owned());
        }
        if self
            .access
            .as_deref()
            .is_some_and(|access| !matches!(access, "" | "none"))
        {
            return Some("access".to_owned());
        }
        if self
            .error
            .as_deref()
            .is_some_and(|error| !matches!(error, "" | "none"))
        {
            return Some("error".to_owned());
        }
        unsupported_non_empty_extra_field(&self.extra)
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn deserialize_log_level_or_null<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.unwrap_or_else(default_log_level))
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundConfig {
    #[serde(
        default = "default_inbound_tag",
        deserialize_with = "deserialize_string_or_null"
    )]
    pub tag: String,
    #[serde(default)]
    pub listen: Option<IpAddr>,
    #[serde(default, deserialize_with = "deserialize_u16_or_null")]
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
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundConfig {
    fn supports_sniffing_destination_override(&self) -> bool {
        matches!(
            &self.protocol,
            InboundProtocol::Socks | InboundProtocol::Http | InboundProtocol::DokodemoDoor
        )
    }

    fn validate_inbound_auth_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        let Some(auth) = settings.auth.as_deref() else {
            return Ok(());
        };
        if auth.is_empty() {
            return Ok(());
        }
        match (self.protocol.clone(), auth) {
            (InboundProtocol::Socks | InboundProtocol::Http, "noauth")
                if settings.accounts.is_empty() =>
            {
                Ok(())
            }
            (InboundProtocol::Socks | InboundProtocol::Http, "password")
                if !settings.accounts.is_empty() =>
            {
                Ok(())
            }
            _ => Err(ConfigError::UnsupportedInboundSettingsField(
                "auth".to_owned(),
            )),
        }
    }

    fn validate_inbound_udp_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        match (self.protocol.clone(), settings.udp) {
            (_, None | Some(false)) | (InboundProtocol::Socks, Some(true)) => Ok(()),
            _ => Err(ConfigError::UnsupportedInboundSettingsField(
                "udp".to_owned(),
            )),
        }
    }

    fn validate_inbound_ip_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        match settings.ip.as_deref() {
            None | Some("") => Ok(()),
            Some(_) => Err(ConfigError::UnsupportedInboundSettingsField(
                "ip".to_owned(),
            )),
        }
    }

    fn validate_inbound_allow_transparent_mode(
        &self,
        settings: &InboundSettings,
    ) -> Result<(), ConfigError> {
        match settings.allow_transparent {
            None | Some(false) => Ok(()),
            Some(true) => Err(ConfigError::UnsupportedInboundSettingsField(
                "allowTransparent".to_owned(),
            )),
        }
    }

    fn validate_inbound_timeout_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        match settings.timeout {
            None | Some(0) => Ok(()),
            Some(_) => Err(ConfigError::UnsupportedInboundSettingsField(
                "timeout".to_owned(),
            )),
        }
    }

    fn validate_inbound_network_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        let Some(network) = settings.network.as_deref() else {
            return Ok(());
        };
        if network.is_empty() {
            return Ok(());
        }
        let parts = network.split(',').map(str::trim).collect::<Vec<_>>();
        if self.protocol == InboundProtocol::DokodemoDoor
            && parts.iter().all(|part| matches!(*part, "tcp" | "udp"))
            && parts.len() <= 2
            && parts.iter().filter(|part| **part == "tcp").count() <= 1
            && parts.iter().filter(|part| **part == "udp").count() <= 1
        {
            return Ok(());
        }
        let non_empty_parts = parts
            .iter()
            .copied()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if self.protocol == InboundProtocol::Shadowsocks
            && !non_empty_parts.is_empty()
            && non_empty_parts
                .iter()
                .all(|part| matches!(*part, "tcp" | "udp"))
        {
            return Ok(());
        }
        Err(ConfigError::UnsupportedInboundSettingsField(
            "network".to_owned(),
        ))
    }

    fn validate_inbound_target_mode(&self, settings: &InboundSettings) -> Result<(), ConfigError> {
        if self.protocol == InboundProtocol::DokodemoDoor
            || (settings.address.as_deref().is_none_or(str::is_empty)
                && settings.port.is_none_or(|port| port == 0))
        {
            return Ok(());
        }
        let field = if settings
            .address
            .as_deref()
            .is_some_and(|address| !address.is_empty())
        {
            "address"
        } else {
            "port"
        };
        Err(ConfigError::UnsupportedInboundSettingsField(
            field.to_owned(),
        ))
    }

    fn validate_inbound_principal_mode(
        &self,
        settings: &InboundSettings,
    ) -> Result<(), ConfigError> {
        if !settings.accounts.is_empty()
            && !matches!(
                self.protocol,
                InboundProtocol::Socks | InboundProtocol::Http
            )
        {
            return Err(ConfigError::UnsupportedInboundSettingsField(
                "accounts".to_owned(),
            ));
        }
        if !settings.clients.is_empty()
            && !matches!(
                self.protocol,
                InboundProtocol::Trojan | InboundProtocol::Vless | InboundProtocol::Vmess
            )
        {
            return Err(ConfigError::UnsupportedInboundSettingsField(
                "clients".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_inbound_client_fields(
        &self,
        settings: &InboundSettings,
    ) -> Result<(), ConfigError> {
        for client in &settings.clients {
            let field = match self.protocol {
                InboundProtocol::Trojan
                    if client.id.as_deref().is_some_and(|id| !id.is_empty()) =>
                {
                    Some("id")
                }
                InboundProtocol::Vless | InboundProtocol::Vmess
                    if client
                        .password
                        .as_deref()
                        .is_some_and(|password| !password.is_empty()) =>
                {
                    Some("password")
                }
                _ => None,
            };
            if let Some(field) = field {
                return Err(ConfigError::UnsupportedInboundClientField(field.to_owned()));
            }
        }
        Ok(())
    }

    fn validate_inbound_decryption_mode(
        &self,
        settings: &InboundSettings,
    ) -> Result<(), ConfigError> {
        if self.protocol == InboundProtocol::Vless
            || settings.decryption.as_deref().is_none_or(str::is_empty)
        {
            return Ok(());
        }
        Err(ConfigError::UnsupportedInboundSettingsField(
            "decryption".to_owned(),
        ))
    }

    fn validate_inbound_credential_mode(
        &self,
        settings: &InboundSettings,
    ) -> Result<(), ConfigError> {
        if self.protocol == InboundProtocol::Shadowsocks
            || (settings.method.as_deref().is_none_or(str::is_empty)
                && settings.password.as_deref().is_none_or(str::is_empty))
        {
            return Ok(());
        }
        let field = if settings
            .method
            .as_deref()
            .is_some_and(|method| !method.is_empty())
        {
            "method"
        } else {
            "password"
        };
        Err(ConfigError::UnsupportedInboundSettingsField(
            field.to_owned(),
        ))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = unsupported_non_empty_extra_field(&self.extra) {
            return Err(ConfigError::UnsupportedInboundSettingsField(field));
        }
        if self.port == 0
            || (self.protocol == InboundProtocol::DokodemoDoor
                && self
                    .settings
                    .as_ref()
                    .is_some_and(|settings| settings.port == Some(0)))
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
            self.validate_inbound_auth_mode(settings)?;
            self.validate_inbound_udp_mode(settings)?;
            self.validate_inbound_ip_mode(settings)?;
            self.validate_inbound_allow_transparent_mode(settings)?;
            self.validate_inbound_timeout_mode(settings)?;
            self.validate_inbound_network_mode(settings)?;
            self.validate_inbound_target_mode(settings)?;
            self.validate_inbound_principal_mode(settings)?;
            self.validate_inbound_client_fields(settings)?;
            self.validate_inbound_decryption_mode(settings)?;
            self.validate_inbound_credential_mode(settings)?;
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
            if settings
                .decryption
                .as_deref()
                .is_some_and(|decryption| decryption != "none")
            {
                return Err(ConfigError::InvalidVlessSettings);
            }
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
                stream_settings.validate_inbound()?;
            }
        }
        if let Some(sniffing) = &self.sniffing
            && (sniffing.has_unsupported_feature()
                || (sniffing.has_effective_override()
                    && !self.supports_sniffing_destination_override()))
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
    #[serde(default, deserialize_with = "deserialize_bool_or_null")]
    pub enabled: bool,
    #[serde(
        default,
        rename = "destOverride",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub dest_override: Vec<String>,
    #[serde(
        default,
        rename = "domainsExcluded",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub domains_excluded: Vec<String>,
    #[serde(
        default,
        rename = "metadataOnly",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub metadata_only: bool,
    #[serde(
        default,
        rename = "routeOnly",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub route_only: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl SniffingConfig {
    fn has_unsupported_feature(&self) -> bool {
        if self.extra.values().any(has_non_empty_value) {
            return true;
        }
        if !self.enabled {
            return false;
        }
        self.dest_override
            .iter()
            .any(|value| !matches!(value.as_str(), "" | "http" | "tls" | "quic"))
            || self
                .domains_excluded
                .iter()
                .any(|domain| validate_routing_rule_domain_matcher(domain).is_err())
    }

    fn has_effective_override(&self) -> bool {
        self.enabled
            && self
                .dest_override
                .iter()
                .any(|value| matches!(value.as_str(), "http" | "tls"))
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
            .as_deref()
            .is_some_and(|strategy| !matches!(strategy, "" | "always"))
            || self
                .refresh
                .is_some_and(|refresh| !matches!(refresh, 0 | 5))
            || self
                .concurrency
                .is_some_and(|concurrency| !matches!(concurrency, 0 | 3))
            || self.extra.values().any(has_non_empty_value)
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
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_inbound_client_vec_or_null"
    )]
    pub clients: Vec<InboundClientConfig>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_inbound_account_vec_or_null"
    )]
    pub accounts: Vec<InboundAccountConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(
        default,
        rename = "allowTransparent",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_transparent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decryption: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedInboundSettingsField(field));
        }
        if self.user_level.is_some_and(|user_level| user_level != 0) {
            return Err(ConfigError::UnsupportedInboundSettingsField(
                "userLevel".to_owned(),
            ));
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
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundAccountConfig {
    #[serde(default, deserialize_with = "deserialize_string_or_null")]
    pub user: String,
    #[serde(default, deserialize_with = "deserialize_string_or_null")]
    pub pass: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundAccountConfig {
    fn unsupported_field(&self) -> Option<String> {
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InboundClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, rename = "alterId", skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl InboundClientConfig {
    fn unsupported_field(&self) -> Option<String> {
        if self.flow.as_deref().is_some_and(|flow| !flow.is_empty()) {
            return Some("flow".to_owned());
        }
        if self.alter_id.is_some_and(|alter_id| alter_id != 0) {
            return Some("alterId".to_owned());
        }
        if self.level.is_some_and(|level| level != 0) {
            return Some("level".to_owned());
        }
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutboundConfig {
    #[serde(
        default = "default_outbound_tag",
        deserialize_with = "deserialize_string_or_null"
    )]
    pub tag: String,
    pub protocol: OutboundProtocol,
    #[serde(
        default,
        rename = "sendThrough",
        skip_serializing_if = "Option::is_none"
    )]
    pub send_through: Option<String>,
    #[serde(
        default,
        rename = "proxySettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy_settings: Option<ProxySettingsConfig>,
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
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl OutboundConfig {
    fn validate_outbound_server_fields(
        &self,
        server: &ProxyServerConfig,
    ) -> Result<(), ConfigError> {
        if !matches!(
            self.protocol,
            OutboundProtocol::Socks | OutboundProtocol::Http
        ) && server.user.is_some()
        {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "user".to_owned(),
            ));
        }
        if !matches!(
            self.protocol,
            OutboundProtocol::Socks
                | OutboundProtocol::Http
                | OutboundProtocol::Shadowsocks
                | OutboundProtocol::Trojan
        ) && server.password.is_some()
        {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "password".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Shadowsocks && server.method.is_some() {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "method".to_owned(),
            ));
        }
        if !matches!(
            self.protocol,
            OutboundProtocol::Vmess | OutboundProtocol::Vless
        ) && server.id.is_some()
        {
            return Err(ConfigError::UnsupportedOutboundServerField("id".to_owned()));
        }
        if self.protocol != OutboundProtocol::Vmess && server.security.is_some() {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "security".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Vless
            && server.extra.get("encryption").is_some_and(|value| {
                value
                    .as_str()
                    .is_some_and(|encryption| !encryption.is_empty())
            })
        {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "encryption".to_owned(),
            ));
        }
        if server.level.is_some_and(|level| level != 0) {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "level".to_owned(),
            ));
        }
        if server
            .email
            .as_deref()
            .is_some_and(|email| !email.is_empty())
        {
            return Err(ConfigError::UnsupportedOutboundServerField(
                "email".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = unsupported_non_empty_extra_field(&self.extra) {
            return Err(ConfigError::UnsupportedOutboundSettingsField(field));
        }
        if let Some(proxy_settings) = &self.proxy_settings
            && proxy_settings.has_unsupported_feature()
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "proxySettings".to_owned(),
            ));
        }
        if let Some(settings) = &self.settings {
            settings.validate()?;
            for server in &settings.servers {
                self.validate_outbound_server_fields(server)?;
            }
            if !settings.servers.is_empty()
                && !matches!(
                    self.protocol,
                    OutboundProtocol::Dns
                        | OutboundProtocol::Socks
                        | OutboundProtocol::Http
                        | OutboundProtocol::Shadowsocks
                        | OutboundProtocol::Trojan
                        | OutboundProtocol::Vmess
                        | OutboundProtocol::Vless
                )
            {
                return Err(ConfigError::UnsupportedOutboundSettingsField(
                    "servers".to_owned(),
                ));
            }
        }
        if matches!(
            self.protocol,
            OutboundProtocol::Dns
                | OutboundProtocol::Socks
                | OutboundProtocol::Http
                | OutboundProtocol::Shadowsocks
                | OutboundProtocol::Trojan
                | OutboundProtocol::Vmess
                | OutboundProtocol::Vless
        ) {
            let settings = self
                .settings
                .as_ref()
                .ok_or(ConfigError::MissingProxyServer)?;
            if settings.servers.len() > 1 {
                return Err(ConfigError::UnsupportedOutboundSettingsField(
                    "servers".to_owned(),
                ));
            }
            let server = settings
                .servers
                .first()
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
            if self.protocol == OutboundProtocol::Trojan
                && server.password.as_deref().is_none_or(str::is_empty)
            {
                return Err(ConfigError::InvalidTrojanSettings);
            }
            if matches!(
                self.protocol,
                OutboundProtocol::Vmess | OutboundProtocol::Vless
            ) {
                for server in &self.settings.as_ref().unwrap().servers {
                    if server
                        .id
                        .as_deref()
                        .is_none_or(|id| Uuid::parse_str(id).is_err())
                    {
                        return Err(ConfigError::InvalidVmessSettings);
                    }
                    if self.protocol == OutboundProtocol::Vmess
                        && let Some(security) = server.security.as_deref()
                        && !matches!(
                            security,
                            "" | "none" | "aes-128-gcm" | "chacha20-poly1305" | "auto"
                        )
                    {
                        return Err(ConfigError::UnsupportedVmessSecurity(security.to_owned()));
                    }
                }
            }
        }
        if let Some(send_through) = self.send_through.as_deref()
            && !send_through.is_empty()
            && (self.protocol != OutboundProtocol::Freedom
                || send_through.parse::<IpAddr>().is_err())
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "sendThrough".to_owned(),
            ));
        }
        if self.protocol == OutboundProtocol::Freedom
            && let Some(settings) = self.settings.as_ref()
        {
            if let Some(redirect) = settings.redirect.as_deref()
                && parse_host_port(redirect).is_none()
            {
                return Err(ConfigError::InvalidFreedomRedirect);
            }
            for domain_strategy in [
                settings.domain_strategy.as_deref(),
                settings.target_strategy.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !matches!(
                    domain_strategy,
                    "" | "AsIs" | "UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4"
                ) {
                    return Err(ConfigError::UnsupportedFreedomDomainStrategy(
                        domain_strategy.to_owned(),
                    ));
                }
            }
            if let Some(proxy_protocol) = settings.proxy_protocol
                && !matches!(proxy_protocol, 0..=2)
            {
                return Err(ConfigError::UnsupportedFreedomProxyProtocol(proxy_protocol));
            }
            if settings
                .fragment
                .as_ref()
                .is_some_and(|value| !is_inert_freedom_fragment(value))
            {
                return Err(ConfigError::UnsupportedFreedomFragment);
            }
            if settings.noises.as_ref().is_some_and(has_non_empty_value) {
                return Err(ConfigError::UnsupportedFreedomNoises);
            }
            if settings
                .final_rules
                .as_ref()
                .is_some_and(has_non_empty_value)
            {
                return Err(ConfigError::UnsupportedFreedomFinalRules);
            }
        }
        if self.protocol != OutboundProtocol::Freedom
            && let Some(redirect) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.redirect.as_deref())
            && !redirect.is_empty()
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "redirect".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && let Some(domain_strategy) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.domain_strategy.as_deref())
            && !matches!(domain_strategy, "" | "AsIs")
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "domainStrategy".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && let Some(target_strategy) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.target_strategy.as_deref())
            && !matches!(target_strategy, "" | "AsIs")
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "targetStrategy".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && let Some(proxy_protocol) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.proxy_protocol)
            && proxy_protocol != 0
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "proxyProtocol".to_owned(),
            ));
        }
        if let Some(user_level) = self
            .settings
            .as_ref()
            .and_then(|settings| settings.user_level)
            && user_level != 0
        {
            if self.protocol == OutboundProtocol::Freedom {
                return Err(ConfigError::UnsupportedFreedomUserLevel(user_level));
            }
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "userLevel".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && self
                .settings
                .as_ref()
                .and_then(|settings| settings.fragment.as_ref())
                .is_some_and(|value| !is_inert_freedom_fragment(value))
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "fragment".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && self
                .settings
                .as_ref()
                .and_then(|settings| settings.noises.as_ref())
                .is_some_and(has_non_empty_value)
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "noises".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Freedom
            && self
                .settings
                .as_ref()
                .and_then(|settings| settings.final_rules.as_ref())
                .is_some_and(has_non_empty_value)
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "finalRules".to_owned(),
            ));
        }
        if self.protocol != OutboundProtocol::Blackhole
            && self
                .settings
                .as_ref()
                .and_then(|settings| settings.response.as_ref())
                .is_some_and(|response| !response.is_inert())
        {
            return Err(ConfigError::UnsupportedOutboundSettingsField(
                "response".to_owned(),
            ));
        }
        if self.protocol == OutboundProtocol::Blackhole
            && let Some(response) = self
                .settings
                .as_ref()
                .and_then(|settings| settings.response.as_ref())
        {
            if let Some(field) = response.unsupported_field() {
                return Err(ConfigError::UnsupportedBlackholeResponseField(field));
            }
            if !matches!(response.kind.as_str(), "" | "http" | "none") {
                return Err(ConfigError::UnsupportedBlackholeResponseType(
                    response.kind.clone(),
                ));
            }
        }
        if let Some(stream_settings) = &self.stream_settings {
            stream_settings
                .validate_with_dialer_proxy(self.protocol == OutboundProtocol::Freedom)?;
            if stream_settings.security.as_deref() == Some("tls")
                && !matches!(
                    self.protocol,
                    OutboundProtocol::Freedom
                        | OutboundProtocol::Socks
                        | OutboundProtocol::Http
                        | OutboundProtocol::Shadowsocks
                        | OutboundProtocol::Trojan
                        | OutboundProtocol::Vmess
                        | OutboundProtocol::Vless
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

fn has_non_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        _ => true,
    }
}

fn is_null_or_empty_object(value: &Value) -> bool {
    matches!(value, Value::Null) || value.as_object().is_some_and(|object| object.is_empty())
}

fn is_inert_freedom_fragment(value: &Value) -> bool {
    is_null_or_empty_object(value)
        || value.as_object().is_some_and(|object| {
            object.iter().all(|(field, value)| {
                matches!(field.as_str(), "packets" | "length" | "interval")
                    && is_empty_or_zero_fragment_value(value)
            })
        })
}

fn is_empty_or_zero_fragment_value(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        let value = value.trim();
        value.is_empty() || value == "0" || value == "0-0"
    }) || value.as_i64() == Some(0)
        || value.as_u64() == Some(0)
}

fn is_inert_raw_tcp_header(value: &Value) -> bool {
    is_null_or_empty_object(value)
        || value.as_object().is_some_and(|object| {
            object.len() == 1
                && object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|header_type| header_type.eq_ignore_ascii_case("none"))
        })
}

fn is_inert_header_value(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(str::is_empty)
        || value.as_array().is_some_and(Vec::is_empty)
}

fn is_inert_top_level_raw_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "acceptProxyProtocol" => {
                value.is_null() || value.as_bool().is_some_and(|enabled| !enabled)
            }
            "header" => is_inert_raw_tcp_header(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_quic_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "security" => {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|security| matches!(security, "" | "none"))
            }
            "key" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "header" => is_inert_raw_tcp_header(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_grpc_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "serviceName" | "authority" => {
                value.is_null() || value.as_str().is_some_and(str::is_empty)
            }
            "user_agent" => value.as_str().is_some_and(str::is_empty),
            "multiMode" | "permit_without_stream" | "noGRPCHeader" => {
                value.is_null() || value.as_bool().is_some_and(|enabled| !enabled)
            }
            "idle_timeout" | "health_check_timeout" | "initial_windows_size" => {
                value.as_u64().is_some_and(|amount| amount == 0)
            }
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_websocket_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "path" | "host" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "headers" => match value {
                Value::Null => true,
                Value::Object(headers) => headers.values().all(is_inert_header_value),
                _ => false,
            },
            "acceptProxyProtocol" => {
                value.is_null() || value.as_bool().is_some_and(|enabled| !enabled)
            }
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_http_upgrade_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "host" | "path" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "headers" => match value {
                Value::Null => true,
                Value::Object(headers) => headers.values().all(is_inert_header_value),
                _ => false,
            },
            "acceptProxyProtocol" => {
                value.is_null() || value.as_bool().is_some_and(|enabled| !enabled)
            }
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_http_transport_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "host" => {
                value.is_null()
                    || value.as_str().is_some_and(str::is_empty)
                    || value.as_array().is_some_and(Vec::is_empty)
            }
            "path" | "method" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "headers" => match value {
                Value::Null => true,
                Value::Object(headers) => headers.values().all(is_inert_header_value),
                _ => false,
            },
            "read_idle_timeout" | "health_check_timeout" => {
                value.as_u64().is_some_and(|timeout| timeout == 0)
            }
            "with_trailers" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_domain_socket_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "path" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "abstract" | "padding" => {
                value.is_null() || value.as_bool().is_some_and(|enabled| !enabled)
            }
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_kcp_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "mtu" => {
                value.is_null()
                    || value
                        .as_u64()
                        .is_some_and(|amount| matches!(amount, 0 | 1350))
            }
            "tti" => {
                value.is_null()
                    || value
                        .as_u64()
                        .is_some_and(|amount| matches!(amount, 0 | 50))
            }
            "uplinkCapacity" => {
                value.is_null() || value.as_u64().is_some_and(|amount| matches!(amount, 0 | 5))
            }
            "downlinkCapacity" => {
                value.is_null()
                    || value
                        .as_u64()
                        .is_some_and(|amount| matches!(amount, 0 | 20))
            }
            "cwndMultiplier" => {
                value.is_null() || value.as_u64().is_some_and(|amount| matches!(amount, 0 | 1))
            }
            "maxSendingWindow" => {
                value.is_null()
                    || value
                        .as_u64()
                        .is_some_and(|amount| matches!(amount, 0 | 2_097_152))
            }
            "readBufferSize" | "writeBufferSize" => {
                value.is_null() || value.as_u64().is_some_and(|amount| amount == 0)
            }
            "congestion" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
            "header" => is_inert_raw_tcp_header(value),
            "seed" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_xhttp_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "path" | "host" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "mode" => {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|mode| matches!(mode, "" | "auto"))
            }
            "headers" => match value {
                Value::Null => true,
                Value::Object(headers) => headers.values().all(is_inert_header_value),
                _ => false,
            },
            "xPaddingKey" => {
                value.is_null() || value.as_str().is_some_and(|key| key == "x_padding")
            }
            "xPaddingHeader" => {
                value.is_null() || value.as_str().is_some_and(|header| header == "X-Padding")
            }
            "xPaddingPlacement" => {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|placement| placement == "queryInHeader")
            }
            "xPaddingMethod" => {
                value.is_null() || value.as_str().is_some_and(|method| method == "repeat-x")
            }
            "uplinkHTTPMethod" => value
                .as_str()
                .is_some_and(|method| matches!(method, "" | "POST")),
            "sessionPlacement" | "seqPlacement" => value
                .as_str()
                .is_some_and(|placement| matches!(placement, "" | "path")),
            "uplinkDataPlacement" => value
                .as_str()
                .is_some_and(|placement| matches!(placement, "" | "auto")),
            "noSSEHeader" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
            "extra" => is_null_or_empty_object(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_top_level_split_http_settings(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "path" | "host" => value.is_null() || value.as_str().is_some_and(str::is_empty),
            "mode" => {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|mode| matches!(mode, "" | "auto"))
            }
            "headers" => match value {
                Value::Null => true,
                Value::Object(headers) => headers.values().all(is_inert_header_value),
                _ => false,
            },
            "scMaxConcurrentPosts" | "xPaddingBytes" => value.is_null(),
            "scMaxEachPostBytes" => is_null_or_exact_i32_range(value, 1_000_000),
            "scMinPostsIntervalMs" => is_null_or_exact_i32_range(value, 30),
            "scMaxBufferedPosts" => {
                value.is_null() || value.as_u64().is_some_and(|posts| posts == 30)
            }
            "uplinkHTTPMethod" => value
                .as_str()
                .is_some_and(|method| matches!(method, "" | "POST")),
            "sessionPlacement" | "seqPlacement" => value
                .as_str()
                .is_some_and(|placement| matches!(placement, "" | "path")),
            "uplinkDataPlacement" => value
                .as_str()
                .is_some_and(|placement| matches!(placement, "" | "auto")),
            "xPaddingKey" => {
                value.is_null() || value.as_str().is_some_and(|key| key == "x_padding")
            }
            "xPaddingHeader" => {
                value.is_null() || value.as_str().is_some_and(|header| header == "X-Padding")
            }
            "xPaddingPlacement" => {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|placement| placement == "queryInHeader")
            }
            "xPaddingMethod" => {
                value.is_null() || value.as_str().is_some_and(|method| method == "repeat-x")
            }
            "noGRPCHeader" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
            "xmux" => is_inert_split_http_xmux(value),
            "extra" => is_null_or_empty_object(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_null_or_exact_i32_range(value: &Value, expected: i64) -> bool {
    value.is_null()
        || value.as_i64().is_some_and(|range| range == expected)
        || value
            .as_str()
            .is_some_and(|range| range.parse::<i64>().is_ok_and(|range| range == expected))
}

fn is_inert_dns_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "servers" => {
                value.is_null()
                    || value
                        .as_array()
                        .is_some_and(|servers| servers.iter().all(is_supported_dns_server_value))
            }
            "hosts" => {
                value.is_null()
                    || value
                        .as_object()
                        .is_some_and(|hosts| hosts.values().all(is_supported_dns_host_value))
            }
            "clientIp" | "clientIP" => value.as_str().is_some_and(|client_ip| {
                client_ip.is_empty() || client_ip.parse::<IpAddr>().is_ok()
            }),
            "tag" => value.as_str().is_some_and(str::is_empty),
            "queryStrategy" => value.as_str().is_some_and(|strategy| {
                matches!(
                    strategy,
                    "" | "UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4"
                )
            }),
            "disableCache" | "serveStale" | "enableParallelQuery" | "useSystemHosts" => {
                value.as_bool().is_some_and(|enabled| !enabled)
            }
            "disableFallback" | "disableFallbackIfMatch" => value.as_bool().is_some(),
            "serveExpiredTTL" => value.as_u64().is_some_and(|ttl| ttl == 0),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_supported_dns_server_value(value: &Value) -> bool {
    value.as_str().is_some_and(is_supported_dns_server_address)
        || value.as_object().is_some_and(|server| {
            server.iter().all(|(field, value)| match field.as_str() {
                "address" => value.as_str().is_some_and(|address| {
                    !address.trim().is_empty() && is_supported_dns_server_address(address)
                }),
                "port" => value
                    .as_u64()
                    .is_some_and(|port| (1..=65535).contains(&port)),
                "domains" => value.as_array().is_some_and(|domains| {
                    domains.iter().all(|domain| {
                        domain.as_str().is_some_and(|domain| {
                            validate_routing_rule_domain_matcher(domain).is_ok()
                        })
                    })
                }),
                "expectIPs" => value.as_array().is_some_and(|ips| {
                    ips.iter().all(|ip| {
                        ip.as_str()
                            .is_some_and(|ip| validate_routing_rule_ip_matcher(ip).is_ok())
                    })
                }),
                "clientIp" | "clientIP" => value.as_str().is_some_and(|client_ip| {
                    client_ip.is_empty() || client_ip.parse::<IpAddr>().is_ok()
                }),
                "queryStrategy" => is_supported_dns_query_strategy(value),
                "skipFallback" => value.is_null() || value.as_bool().is_some(),
                _ => !has_non_empty_value(value),
            }) && server
                .get("address")
                .is_some_and(|address| address.as_str().is_some())
        })
}

fn is_supported_dns_server_address(address: &str) -> bool {
    if address.trim().is_empty() {
        return false;
    }

    if let Some(address) = address
        .strip_prefix("tcp://")
        .or_else(|| address.strip_prefix("udp://"))
    {
        return is_supported_dns_server_uri_authority(address);
    }

    !address.contains("://")
}

fn is_supported_dns_server_uri_authority(address: &str) -> bool {
    if let Some(address) = address.strip_prefix('[') {
        let Some((_, rest)) = address.split_once(']') else {
            return false;
        };
        if rest.is_empty() {
            return true;
        }
        let Some(port) = rest.strip_prefix(':') else {
            return false;
        };
        return port.parse::<u16>().is_ok_and(|port| port != 0);
    }

    if address.matches(':').count() == 1 {
        let Some((address, port)) = address.rsplit_once(':') else {
            return false;
        };
        return !address.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0);
    }

    !address.is_empty()
}

fn is_supported_dns_query_strategy(value: &Value) -> bool {
    value.as_str().is_some_and(|strategy| {
        matches!(
            strategy,
            "" | "UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4"
        )
    })
}

fn is_supported_dns_host_value(value: &Value) -> bool {
    value.as_str().is_some()
        || value
            .as_array()
            .is_some_and(|addresses| addresses.iter().all(|address| address.as_str().is_some()))
}

fn is_empty_dns_merge_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "servers" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
            "hosts" => value.is_null() || value.as_object().is_some_and(|hosts| hosts.is_empty()),
            "clientIp" | "clientIP" | "tag" => value.as_str().is_some_and(str::is_empty),
            "queryStrategy" => value
                .as_str()
                .is_some_and(|strategy| matches!(strategy, "" | "UseIP")),
            "disableCache"
            | "serveStale"
            | "disableFallback"
            | "disableFallbackIfMatch"
            | "enableParallelQuery"
            | "useSystemHosts" => value.as_bool().is_some_and(|enabled| !enabled),
            "serveExpiredTTL" => value.as_u64().is_some_and(|ttl| ttl == 0),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_api_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "tag" => value.as_str().is_some_and(str::is_empty),
            "services" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_geodata_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "loader" => value.as_str().is_some_and(|loader| loader == "standard"),
            "geoip" => value.as_str().is_some_and(|geoip| geoip == "geoip.dat"),
            "geosite" => value
                .as_str()
                .is_some_and(|geosite| geosite == "geosite.dat"),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_stats_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.values().all(|value| !has_non_empty_value(value)),
        _ => false,
    }
}

fn is_inert_fakedns_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(entries) => entries.iter().all(is_inert_fakedns_entry),
        Value::Object(_) => is_inert_fakedns_entry(value),
        _ => false,
    }
}

fn is_inert_fakedns_entry(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "ipPool" => value.as_str().is_some_and(str::is_empty),
            "poolSize" => value.as_u64().is_some_and(|size| size == 0),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_policy_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "levels" => is_supported_policy_levels(value),
            "system" => is_supported_policy_system(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_supported_policy_system(value: &Value) -> bool {
    value.is_null()
        || value.as_object().is_some_and(|fields| {
            fields.iter().all(|(field, value)| {
                matches!(
                    field.as_str(),
                    "statsInboundUplink"
                        | "statsInboundDownlink"
                        | "statsOutboundUplink"
                        | "statsOutboundDownlink"
                ) && value.as_bool().is_some()
            })
        })
}

fn is_supported_policy_levels(value: &Value) -> bool {
    value.is_null()
        || value.as_object().is_some_and(|levels| {
            levels.iter().all(|(level, value)| {
                level.parse::<u32>().is_ok()
                    && value.as_object().is_some_and(|fields| {
                        fields.iter().all(|(field, value)| match field.as_str() {
                            "handshake" => level == "0" && value.as_u64().is_some(),
                            "connIdle" => {
                                level == "0" && value.as_u64().is_some_and(|seconds| seconds == 300)
                            }
                            "uplinkOnly" | "downlinkOnly" => {
                                level == "0" && value.as_u64().is_some_and(|seconds| seconds == 1)
                            }
                            "statsUserUplink" | "statsUserDownlink" => {
                                value.as_bool().is_some_and(|enabled| !enabled)
                            }
                            _ => false,
                        })
                    })
            })
        })
}

fn is_inert_metrics_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "tag" => value.as_str().is_some_and(str::is_empty),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_observatory_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => {
            let selector_is_inert = fields.get("subjectSelector").is_none_or(|selector| {
                selector.is_null() || selector.as_array().is_some_and(Vec::is_empty)
            });
            fields.iter().all(|(field, value)| match field.as_str() {
                "subjectSelector" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
                "probeURL" => {
                    selector_is_inert
                        && value.as_str().is_some_and(|probe_url| {
                            matches!(probe_url, "" | "https://www.google.com/generate_204")
                        })
                }
                _ => !has_non_empty_value(value),
            })
        }
        _ => false,
    }
}

fn is_inert_reverse_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "bridges" | "portals" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_burst_observatory_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => {
            let selector_is_inert = fields.get("subjectSelector").is_none_or(|selector| {
                selector.is_null() || selector.as_array().is_some_and(Vec::is_empty)
            });
            fields.iter().all(|(field, value)| match field.as_str() {
                "subjectSelector" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
                "pingConfig" => selector_is_inert && is_inert_burst_observatory_ping_config(value),
                _ => !has_non_empty_value(value),
            })
        }
        _ => false,
    }
}

fn is_inert_burst_observatory_ping_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "destination" => value.as_str().is_some_and(|destination| {
                matches!(destination, "" | "https://www.google.com/generate_204")
            }),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn is_inert_browser_forwarder_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.values().all(|value| !has_non_empty_value(value)),
        _ => false,
    }
}

fn is_inert_top_level_transport_config(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "rawSettings" => is_inert_top_level_raw_settings(value),
            "quicSettings" => is_inert_top_level_quic_settings(value),
            "grpcSettings" => is_inert_top_level_grpc_settings(value),
            "wsSettings" => is_inert_top_level_websocket_settings(value),
            "httpupgradeSettings" => is_inert_top_level_http_upgrade_settings(value),
            "httpSettings" => is_inert_top_level_http_transport_settings(value),
            "dsSettings" => is_inert_top_level_domain_socket_settings(value),
            "xhttpSettings" => is_inert_top_level_xhttp_settings(value),
            "splithttpSettings" => is_inert_top_level_split_http_settings(value),
            "kcpSettings" => is_inert_top_level_kcp_settings(value),
            "tcpSettings" => is_inert_top_level_raw_settings(value),
            _ => !has_non_empty_value(value),
        }),
        _ => false,
    }
}

fn merge_top_level_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if has_non_empty_value(current_value) && !has_non_empty_value(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_fakedns_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_fakedns_config(current_value) && is_inert_fakedns_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_stats_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_stats_config(current_value) && is_inert_stats_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_api_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_api_config(current_value) && is_inert_api_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_policy_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_policy_config(current_value) && is_inert_policy_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_metrics_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_metrics_config(current_value) && is_inert_metrics_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_dns_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_empty_dns_merge_value(current_value)
                && is_empty_dns_merge_value(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_observatory_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_observatory_config(current_value)
                && is_inert_observatory_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_burst_observatory_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_burst_observatory_config(current_value)
                && is_inert_burst_observatory_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_browser_forwarder_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_browser_forwarder_config(current_value)
                && is_inert_browser_forwarder_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_geodata_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_geodata_config(current_value) && is_inert_geodata_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_reverse_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_reverse_config(current_value) && is_inert_reverse_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_transport_value(current: &mut Option<Value>, next: Option<Value>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if !is_inert_top_level_transport_config(current_value)
                && is_inert_top_level_transport_config(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn merge_inert_extra_fields(current: &mut BTreeMap<String, Value>, next: BTreeMap<String, Value>) {
    for (field, value) in next {
        match current.get(&field) {
            Some(current_value)
                if has_non_empty_value(current_value) || !has_non_empty_value(&value) => {}
            _ => {
                current.insert(field, value);
            }
        }
    }
}

fn merge_log_output(current: &mut Option<String>, next: Option<String>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if is_unsupported_log_output(current_value) && is_disabled_log_output(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn is_unsupported_log_output(value: &str) -> bool {
    !is_disabled_log_output(value)
}

fn is_disabled_log_output(value: &str) -> bool {
    matches!(value, "" | "none")
}

fn merge_routing_domain_strategy(current: &mut Option<String>, next: Option<String>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if is_unsupported_routing_domain_strategy(current_value)
                && is_supported_routing_domain_strategy(&next_value) => {}
        Some(current_value)
            if is_active_routing_domain_strategy(current_value)
                && is_default_routing_domain_strategy(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn is_supported_routing_domain_strategy(domain_strategy: &str) -> bool {
    matches!(
        domain_strategy,
        "" | "AsIs"
            | "IPIfNonMatch"
            | "IPOnDemand"
            | "UseIP"
            | "UseIPv4"
            | "UseIPv6"
            | "UseIPv4v6"
            | "UseIPv6v4"
    )
}

fn is_unsupported_routing_domain_strategy(domain_strategy: &str) -> bool {
    !is_supported_routing_domain_strategy(domain_strategy)
}

fn is_default_routing_domain_strategy(domain_strategy: &str) -> bool {
    matches!(domain_strategy, "" | "AsIs" | "UseIP")
}

fn is_active_routing_domain_strategy(domain_strategy: &str) -> bool {
    is_supported_routing_domain_strategy(domain_strategy)
        && !is_default_routing_domain_strategy(domain_strategy)
}

fn merge_routing_domain_matcher(current: &mut Option<String>, next: Option<String>) {
    let Some(next_value) = next else {
        return;
    };

    match current {
        Some(current_value)
            if is_unsupported_routing_domain_matcher(current_value)
                && !is_unsupported_routing_domain_matcher(&next_value) => {}
        _ => *current = Some(next_value),
    }
}

fn is_unsupported_routing_domain_matcher(domain_matcher: &str) -> bool {
    !matches!(domain_matcher, "" | "linear" | "mph" | "hybrid")
}

fn unsupported_extra_field(extra: &BTreeMap<String, Value>) -> Option<String> {
    extra
        .iter()
        .find(|(_, value)| !value.is_null())
        .map(|(field, _)| field.clone())
}

fn unsupported_non_empty_extra_field(extra: &BTreeMap<String, Value>) -> Option<String> {
    extra
        .iter()
        .find(|(_, value)| has_non_empty_value(value))
        .map(|(field, _)| field.clone())
}

fn unsupported_routing_attrs(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.is_empty() && parse_routing_attrs_matcher(value).is_none(),
        value => has_non_empty_value(value),
    }
}

fn parse_routing_attrs_matcher(value: &str) -> Option<()> {
    parse_routing_attrs_or_matcher(value).or_else(|| parse_routing_attrs_non_or_matcher(value))
}

fn parse_routing_attrs_or_matcher(value: &str) -> Option<()> {
    let mut operands = value.split(" || ");
    parse_routing_attrs_non_or_matcher(operands.next()?)?;
    parse_routing_attrs_non_or_matcher(operands.next()?)?;
    operands.try_for_each(parse_routing_attrs_non_or_matcher)
}

fn parse_routing_attrs_non_or_matcher(value: &str) -> Option<()> {
    let value = strip_routing_attrs_parentheses(value).unwrap_or(value);

    parse_routing_attrs_method_matcher(value)
        .map(|_| ())
        .or_else(|| parse_routing_attrs_method_not_matcher(value).map(|_| ()))
        .or_else(|| parse_routing_attrs_path_matcher(value).map(|_| ()))
        .or_else(|| parse_routing_attrs_path_not_matcher(value).map(|_| ()))
        .or_else(|| parse_routing_attrs_path_prefix_matcher(value).map(|_| ()))
        .or_else(|| parse_routing_attrs_path_contains_matcher(value).map(|_| ()))
        .or_else(|| parse_routing_attrs_compound_matcher(value).then_some(()))
}

fn strip_routing_attrs_parentheses(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0;
    let mut quote = None;

    for (index, ch) in value.char_indices() {
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && index != value.len() - 1 {
                    return None;
                }
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }

    (depth == 0 && quote.is_none()).then_some(inner)
}

fn parse_routing_attrs_compound_matcher(value: &str) -> bool {
    let operands = value.split(" && ").collect::<Vec<_>>();
    if operands.len() < 2 {
        return false;
    }

    let mut has_method = false;
    let mut has_path = false;
    for operand in operands {
        if parse_routing_attrs_method_like(operand) {
            has_method = true;
        } else if parse_routing_attrs_path_like(operand) {
            has_path = true;
        } else {
            return false;
        }
    }

    has_method && has_path
}

fn parse_routing_attrs_method_like(value: &str) -> bool {
    let value = strip_routing_attrs_parentheses(value).unwrap_or(value);

    parse_routing_attrs_method_matcher(value).is_some()
        || parse_routing_attrs_method_not_matcher(value).is_some()
}

fn parse_routing_attrs_path_like(value: &str) -> bool {
    let value = strip_routing_attrs_parentheses(value).unwrap_or(value);

    parse_routing_attrs_path_matcher(value).is_some()
        || parse_routing_attrs_path_not_matcher(value).is_some()
        || parse_routing_attrs_path_prefix_matcher(value).is_some()
        || parse_routing_attrs_path_contains_matcher(value).is_some()
}

fn parse_routing_attrs_method_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":method", "==", "'")
        .filter(|method| !method.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":method", "==", "\"")
                .filter(|method| !method.contains('"'))
        })
        .filter(|method| http_method_token(method))
}

fn parse_routing_attrs_method_not_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":method", "!=", "'")
        .filter(|method| !method.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":method", "!=", "\"")
                .filter(|method| !method.contains('"'))
        })
        .filter(|method| http_method_token(method))
}

fn parse_routing_attrs_path_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":path", "==", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":path", "==", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_routing_attrs_path_not_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":path", "!=", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":path", "!=", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_routing_attrs_path_prefix_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_call_value(value, ":path", "startswith", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_call_value(value, ":path", "startswith", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_routing_attrs_path_contains_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_call_value(value, ":path", "contains", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_call_value(value, ":path", "contains", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_quoted_attrs_value<'a>(
    value: &'a str,
    name: &str,
    operator: &str,
    quote: &str,
) -> Option<&'a str> {
    value
        .strip_prefix(&format!("attrs['{name}'] {operator} {quote}"))
        .or_else(|| value.strip_prefix(&format!("attrs[\"{name}\"] {operator} {quote}")))?
        .strip_suffix(quote)
}

fn parse_quoted_attrs_call_value<'a>(
    value: &'a str,
    name: &str,
    function: &str,
    quote: &str,
) -> Option<&'a str> {
    value
        .strip_prefix(&format!("attrs['{name}'].{function}({quote}"))
        .or_else(|| value.strip_prefix(&format!("attrs[\"{name}\"].{function}({quote}")))?
        .strip_suffix(&format!("{quote})"))
}

fn http_method_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'))
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
    Trojan,
    Vless,
    Vmess,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProxySettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ProxySettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MuxConfig {
    #[serde(default, deserialize_with = "deserialize_bool_or_null")]
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
    #[serde(
        default,
        rename = "xudpProxyUDP443",
        deserialize_with = "deserialize_string_or_null"
    )]
    pub xudp_proxy_udp443: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl MuxConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.enabled
            || self
                .concurrency
                .is_some_and(|value| !matches!(value, -1 | 0 | 8))
            || self.xudp_concurrency.is_some_and(|value| value != 0)
            || !matches!(self.xudp_proxy_udp443.as_str(), "" | "reject" | "skip")
            || self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OutboundSettings {
    #[serde(default, deserialize_with = "deserialize_proxy_server_vec_or_null")]
    pub servers: Vec<ProxyServerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<BlackholeResponseConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(
        default,
        rename = "domainStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_strategy: Option<String>,
    #[serde(
        default,
        rename = "targetStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub target_strategy: Option<String>,
    #[serde(
        default,
        rename = "proxyProtocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy_protocol: Option<u8>,
    #[serde(default, rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noises: Option<Value>,
    #[serde(
        default,
        rename = "finalRules",
        skip_serializing_if = "Option::is_none"
    )]
    pub final_rules: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl OutboundSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(field) = self.unsupported_field() {
            return Err(ConfigError::UnsupportedOutboundSettingsField(field));
        }
        for server in &self.servers {
            if let Some(field) = server.unsupported_field() {
                return Err(ConfigError::UnsupportedOutboundServerField(field));
            }
        }
        Ok(())
    }

    fn unsupported_field(&self) -> Option<String> {
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlackholeResponseConfig {
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_string_or_null"
    )]
    pub kind: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl BlackholeResponseConfig {
    fn unsupported_field(&self) -> Option<String> {
        unsupported_non_empty_extra_field(&self.extra)
    }

    fn is_inert(&self) -> bool {
        matches!(self.kind.as_str(), "" | "none")
            && self.extra.values().all(|value| !has_non_empty_value(value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyServerConfig {
    #[serde(default, deserialize_with = "deserialize_string_or_null")]
    pub address: String,
    #[serde(default, deserialize_with = "deserialize_u16_or_null")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, rename = "alterId", skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ProxyServerConfig {
    fn unsupported_field(&self) -> Option<String> {
        if self.flow.as_deref().is_some_and(|flow| !flow.is_empty()) {
            return Some("flow".to_owned());
        }
        if self.alter_id.is_some_and(|alter_id| alter_id != 0) {
            return Some("alterId".to_owned());
        }
        self.extra
            .iter()
            .find(|(field, value)| proxy_server_extra_field_is_unsupported(field, value))
            .map(|(field, _)| field.clone())
    }
}

fn proxy_server_extra_field_is_unsupported(field: &str, value: &Value) -> bool {
    if field == "encryption" {
        return value
            .as_str()
            .is_none_or(|encryption| !matches!(encryption, "" | "none"));
    }
    has_non_empty_value(value)
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
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl StreamSettingsConfig {
    fn validate_common_with_raw_validator(
        &self,
        has_unsupported_raw_feature: fn(&RawSettingsConfig) -> bool,
    ) -> Result<(), ConfigError> {
        self.validate_common_with_options(has_unsupported_raw_feature, false)
    }

    fn validate_common_with_options(
        &self,
        has_unsupported_raw_feature: fn(&RawSettingsConfig) -> bool,
        allow_dialer_proxy: bool,
    ) -> Result<(), ConfigError> {
        if let Some(field) = unsupported_non_empty_extra_field(&self.extra) {
            return Err(ConfigError::UnsupportedStreamSettingsField(field));
        }
        if let Some(network) = &self.network
            && !network.is_empty()
            && network != "raw"
            && network != "tcp"
        {
            return Err(ConfigError::UnsupportedTransportNetwork(network.clone()));
        }
        let selected_network = self
            .network
            .as_deref()
            .filter(|network| !network.is_empty())
            .unwrap_or("tcp");
        if self
            .raw_settings
            .as_ref()
            .is_some_and(has_unsupported_raw_feature)
            || self
                .tcp_settings
                .as_ref()
                .is_some_and(has_unsupported_raw_feature)
        {
            return Err(ConfigError::UnsupportedRawTransportFeature);
        }
        if self.security.as_deref() == Some("reality")
            && self
                .reality_settings
                .as_ref()
                .is_some_and(RealitySettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedRealityTransportFeature);
        }
        if selected_network == "ws"
            && self
                .ws_settings
                .as_ref()
                .is_some_and(WebSocketSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedWebSocketTransportFeature);
        }
        if selected_network == "grpc"
            && self
                .grpc_settings
                .as_ref()
                .is_some_and(GrpcSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedGrpcTransportFeature);
        }
        if selected_network == "xhttp"
            && self
                .xhttp_settings
                .as_ref()
                .is_some_and(XhttpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedXhttpTransportFeature);
        }
        if selected_network == "splithttp"
            && self
                .split_http_settings
                .as_ref()
                .is_some_and(SplitHttpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedSplitHttpTransportFeature);
        }
        if selected_network == "httpupgrade"
            && self
                .http_upgrade_settings
                .as_ref()
                .is_some_and(HttpUpgradeSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedHttpUpgradeTransportFeature);
        }
        if selected_network == "http"
            && self
                .http_settings
                .as_ref()
                .is_some_and(HttpTransportSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedHttpTransportFeature);
        }
        if selected_network == "kcp"
            && self
                .kcp_settings
                .as_ref()
                .is_some_and(KcpSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedKcpTransportFeature);
        }
        if selected_network == "quic"
            && self
                .quic_settings
                .as_ref()
                .is_some_and(QuicSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedQuicTransportFeature);
        }
        if selected_network == "domainsocket"
            && self
                .ds_settings
                .as_ref()
                .is_some_and(DomainSocketSettingsConfig::has_unsupported_feature)
        {
            return Err(ConfigError::UnsupportedDomainSocketTransportFeature);
        }
        if self.sockopt.as_ref().is_some_and(|sockopt| {
            sockopt.has_unsupported_feature_with_dialer_proxy(allow_dialer_proxy)
        }) {
            return Err(ConfigError::UnsupportedSockoptFeature);
        }
        Ok(())
    }

    fn validate_with_dialer_proxy(&self, allow_dialer_proxy: bool) -> Result<(), ConfigError> {
        self.validate_common_with_options(
            RawSettingsConfig::has_unsupported_feature,
            allow_dialer_proxy,
        )?;
        if let Some(security) = &self.security
            && !security.is_empty()
            && security != "none"
            && security != "tls"
        {
            return Err(ConfigError::UnsupportedTransportSecurity(security.clone()));
        }
        if self.security.as_deref() == Some("tls")
            && self.tls_settings.as_ref().is_some_and(|settings| {
                settings.has_unsupported_outbound_feature()
                    || settings.server_name.as_deref().is_some_and(|server_name| {
                        !server_name.is_empty() && server_name != server_name.trim()
                    })
                    || settings
                        .alpn
                        .iter()
                        .any(|protocol| !protocol.is_empty() && protocol.trim().is_empty())
                    || (settings.alpn.iter().any(|protocol| !protocol.is_empty())
                        && !tls_alpn_supported())
            })
        {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        }
        Ok(())
    }

    fn validate_inbound(&self) -> Result<(), ConfigError> {
        self.validate_common_with_raw_validator(
            RawSettingsConfig::has_unsupported_inbound_feature,
        )?;
        if self
            .sockopt
            .as_ref()
            .is_some_and(|sockopt| sockopt.tcp_fast_open)
        {
            return Err(ConfigError::UnsupportedSockoptFeature);
        }
        if let Some(security) = &self.security
            && !security.is_empty()
            && security != "none"
        {
            return Err(ConfigError::UnsupportedTransportSecurity(security.clone()));
        }
        Ok(())
    }

    fn validate_inbound_tls(&self) -> Result<(), ConfigError> {
        self.validate_common_with_raw_validator(
            RawSettingsConfig::has_unsupported_inbound_feature,
        )?;
        let Some(tls_settings) = &self.tls_settings else {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        };
        if tls_settings
            .server_name
            .as_ref()
            .is_some_and(|server_name| server_name != server_name.trim())
        {
            return Err(ConfigError::UnsupportedInboundTlsSettingsField(
                "serverName".to_owned(),
            ));
        }
        for certificate in &tls_settings.certificates {
            if let Some(field) = certificate.unsupported_field() {
                return Err(ConfigError::UnsupportedInboundTlsSettingsField(field));
            }
        }
        if tls_settings.has_unsupported_inbound_tls_feature()
            || !tls_settings.has_usable_inbound_certificate()
        {
            return Err(ConfigError::UnsupportedTlsTransportFeature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawSettingsConfig {
    #[serde(
        default,
        rename = "acceptProxyProtocol",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub accept_proxy_protocol: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RawSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.accept_proxy_protocol
            || self
                .header
                .as_ref()
                .is_some_and(|header| !is_inert_raw_tcp_header(header))
            || self.extra.values().any(has_non_empty_value)
    }

    fn has_unsupported_inbound_feature(&self) -> bool {
        self.header
            .as_ref()
            .is_some_and(|header| !is_inert_raw_tcp_header(header))
            || self.extra.values().any(has_non_empty_value)
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
    #[serde(
        default,
        rename = "allowInsecure",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub allow_insecure: bool,
    #[serde(
        default,
        rename = "alpn",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub alpn: Vec<String>,
    #[serde(
        default,
        rename = "certificates",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_tls_certificate_vec_or_null"
    )]
    pub certificates: Vec<TlsCertificateConfig>,
    #[serde(
        default,
        rename = "disableSystemRoot",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
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
        self.certificates.iter().any(|certificate| {
            certificate.has_usable_files() || certificate.unsupported_field().is_some()
        }) || self.disable_system_root
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.is_empty())
            || !self.pinned_peer_certificate_chain_sha256.is_empty()
            || self.extra.values().any(has_non_empty_value)
    }

    fn has_unsupported_inbound_tls_feature(&self) -> bool {
        self.allow_insecure
            || self.alpn.iter().any(|protocol| protocol.trim().is_empty())
            || (!self.alpn.is_empty() && !tls_alpn_supported())
            || self.disable_system_root
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.is_empty())
            || !self.pinned_peer_certificate_chain_sha256.is_empty()
            || self.extra.values().any(has_non_empty_value)
    }

    fn has_usable_inbound_certificate(&self) -> bool {
        self.certificates.len() == 1
            && self.certificates[0].has_usable_files()
            && fs::read(self.certificates[0].certificate_file.as_ref().unwrap()).is_ok()
            && fs::read(self.certificates[0].key_file.as_ref().unwrap()).is_ok()
    }
}

impl TlsCertificateConfig {
    fn unsupported_field(&self) -> Option<String> {
        unsupported_extra_field(&self.extra)
    }

    fn has_usable_files(&self) -> bool {
        self.certificate_file
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
            && self
                .key_file
                .as_ref()
                .is_some_and(|path| !path.as_os_str().is_empty())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RealitySettingsConfig {
    #[serde(
        default,
        rename = "show",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub show: bool,
    #[serde(default, rename = "dest", skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(
        default,
        rename = "serverNames",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub server_names: Vec<String>,
    #[serde(
        default,
        rename = "privateKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<String>,
    #[serde(default, rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(
        default,
        rename = "shortIds",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
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
            || self.extra.values().any(has_non_empty_value)
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
    #[serde(
        default,
        rename = "acceptProxyProtocol",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub accept_proxy_protocol: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl WebSocketSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self.headers.as_ref().is_some_and(|headers| match headers {
                Value::Null => false,
                Value::Object(map) => !map.values().all(is_inert_header_value),
                _ => true,
            })
            || self.accept_proxy_protocol
            || self.extra.values().any(has_non_empty_value)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(
        default,
        rename = "multiMode",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
    #[serde(
        default,
        rename = "permit_without_stream",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub permit_without_stream: bool,
    #[serde(
        default,
        rename = "initial_windows_size",
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_windows_size: Option<u64>,
    #[serde(
        default,
        rename = "noGRPCHeader",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub no_grpc_header: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl GrpcSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.service_name
            .as_ref()
            .is_some_and(|service_name| !service_name.is_empty())
            || self
                .authority
                .as_ref()
                .is_some_and(|authority| !authority.is_empty())
            || self.multi_mode
            || self.idle_timeout.is_some_and(|timeout| timeout != 0)
            || self
                .health_check_timeout
                .is_some_and(|timeout| timeout != 0)
            || self.permit_without_stream
            || self.initial_windows_size.is_some_and(|size| size != 0)
            || self.no_grpc_header
            || self
                .extra
                .iter()
                .any(|(field, value)| match field.as_str() {
                    "user_agent" => !value.as_str().is_some_and(str::is_empty),
                    _ => has_non_empty_value(value),
                })
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
            || self
                .mode
                .as_deref()
                .is_some_and(|mode| !matches!(mode, "" | "auto"))
            || self.headers.as_ref().is_some_and(|headers| match headers {
                Value::Null => false,
                Value::Object(map) => !map.values().all(is_inert_header_value),
                _ => true,
            })
            || self
                .extra_config
                .as_ref()
                .is_some_and(|extra| !is_null_or_empty_object(extra))
            || self
                .extra
                .iter()
                .any(|(field, value)| !is_inert_xhttp_extra_field(field, value))
    }
}

fn is_inert_xhttp_extra_field(field: &str, value: &Value) -> bool {
    match field {
        "xPaddingKey" => value.is_null() || value.as_str().is_some_and(|key| key == "x_padding"),
        "xPaddingHeader" => {
            value.is_null() || value.as_str().is_some_and(|header| header == "X-Padding")
        }
        "xPaddingPlacement" => {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|placement| placement == "queryInHeader")
        }
        "xPaddingMethod" => {
            value.is_null() || value.as_str().is_some_and(|method| method == "repeat-x")
        }
        "uplinkHTTPMethod" => value
            .as_str()
            .is_some_and(|method| matches!(method, "" | "POST")),
        "sessionPlacement" | "seqPlacement" => value
            .as_str()
            .is_some_and(|placement| matches!(placement, "" | "path")),
        "uplinkDataPlacement" => value
            .as_str()
            .is_some_and(|placement| matches!(placement, "" | "auto")),
        "noSSEHeader" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
        _ => !has_non_empty_value(value),
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
            || self
                .mode
                .as_deref()
                .is_some_and(|mode| !matches!(mode, "" | "auto"))
            || self.headers.as_ref().is_some_and(|headers| match headers {
                Value::Null => false,
                Value::Object(map) => !map.values().all(is_inert_header_value),
                _ => true,
            })
            || self
                .sc_max_concurrent_posts
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self.sc_max_buffered_posts.as_ref().is_some_and(|value| {
                !(value.is_null() || value.as_u64().is_some_and(|posts| posts == 30))
            })
            || self
                .sc_max_each_post_bytes
                .as_ref()
                .is_some_and(|value| !is_null_or_exact_i32_range(value, 1_000_000))
            || self
                .sc_min_posts_interval_ms
                .as_ref()
                .is_some_and(|value| !is_null_or_exact_i32_range(value, 30))
            || self
                .x_padding_bytes
                .as_ref()
                .is_some_and(|value| !value.is_null())
            || self
                .xmux
                .as_ref()
                .is_some_and(|xmux| !is_inert_split_http_xmux(xmux))
            || self
                .extra_config
                .as_ref()
                .is_some_and(|extra| !is_null_or_empty_object(extra))
            || self
                .extra
                .iter()
                .any(|(field, value)| !is_inert_split_http_extra_field(field, value))
    }
}

fn is_inert_split_http_xmux(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.iter().all(|(field, value)| match field.as_str() {
            "maxConcurrency" | "maxConnections" | "cMaxReuseTimes" | "hMaxRequestTimes"
            | "hMaxReusableSecs" => is_zero_range_config(value),
            "hKeepAlivePeriod" => value.as_i64().is_some_and(|period| period == 0),
            _ => false,
        }),
        _ => false,
    }
}

fn is_zero_range_config(value: &Value) -> bool {
    value.as_object().is_some_and(|range| {
        range.len() == 2
            && range
                .get("from")
                .is_some_and(|value| value.as_i64().is_some_and(|bound| bound == 0))
            && range
                .get("to")
                .is_some_and(|value| value.as_i64().is_some_and(|bound| bound == 0))
    })
}

fn is_inert_split_http_extra_field(field: &str, value: &Value) -> bool {
    match field {
        "xPaddingKey" => value.is_null() || value.as_str().is_some_and(|key| key == "x_padding"),
        "xPaddingHeader" => {
            value.is_null() || value.as_str().is_some_and(|header| header == "X-Padding")
        }
        "xPaddingPlacement" => {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|placement| placement == "queryInHeader")
        }
        "xPaddingMethod" => {
            value.is_null() || value.as_str().is_some_and(|method| method == "repeat-x")
        }
        "uplinkHTTPMethod" => value
            .as_str()
            .is_some_and(|method| matches!(method, "" | "POST")),
        "sessionPlacement" | "seqPlacement" => value
            .as_str()
            .is_some_and(|placement| matches!(placement, "" | "path")),
        "uplinkDataPlacement" => value
            .as_str()
            .is_some_and(|placement| matches!(placement, "" | "auto")),
        "noGRPCHeader" => value.is_null() || value.as_bool().is_some_and(|enabled| !enabled),
        _ => !has_non_empty_value(value),
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
    #[serde(
        default,
        rename = "acceptProxyProtocol",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub accept_proxy_protocol: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl HttpUpgradeSettingsConfig {
    fn has_unsupported_feature(&self) -> bool {
        self.host.as_ref().is_some_and(|host| !host.is_empty())
            || self.path.as_ref().is_some_and(|path| !path.is_empty())
            || self.headers.as_ref().is_some_and(|headers| match headers {
                Value::Null => false,
                Value::Object(map) => !map.values().all(is_inert_header_value),
                _ => true,
            })
            || self.accept_proxy_protocol
            || self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HttpTransportSettingsConfig {
    #[serde(
        default,
        rename = "host",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
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
    #[serde(
        default,
        rename = "with_trailers",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
            || self.headers.as_ref().is_some_and(|headers| match headers {
                Value::Null => false,
                Value::Object(map) => !map.values().all(is_inert_header_value),
                _ => true,
            })
            || self.read_idle_timeout.is_some_and(|timeout| timeout != 0)
            || self
                .health_check_timeout
                .is_some_and(|timeout| timeout != 0)
            || self.with_trailers
            || self.extra.values().any(has_non_empty_value)
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
    #[serde(
        default,
        rename = "congestion",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
        self.mtu.is_some_and(|mtu| !matches!(mtu, 0 | 1350))
            || self.tti.is_some_and(|tti| !matches!(tti, 0 | 50))
            || self
                .uplink_capacity
                .is_some_and(|uplink_capacity| !matches!(uplink_capacity, 0 | 5))
            || self
                .downlink_capacity
                .is_some_and(|downlink_capacity| !matches!(downlink_capacity, 0 | 20))
            || self.congestion
            || self
                .read_buffer_size
                .is_some_and(|read_buffer_size| read_buffer_size != 0)
            || self
                .write_buffer_size
                .is_some_and(|write_buffer_size| write_buffer_size != 0)
            || self
                .header
                .as_ref()
                .is_some_and(|header| !is_inert_raw_tcp_header(header))
            || self.seed.as_ref().is_some_and(|seed| !seed.is_empty())
            || self
                .extra
                .iter()
                .any(|(field, value)| match field.as_str() {
                    "cwndMultiplier" => {
                        !value.as_u64().is_some_and(|amount| matches!(amount, 0 | 1))
                    }
                    "maxSendingWindow" => !value
                        .as_u64()
                        .is_some_and(|amount| matches!(amount, 0 | 2_097_152)),
                    _ => has_non_empty_value(value),
                })
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
            .is_some_and(|security| !matches!(security.as_str(), "" | "none"))
            || self.key.as_ref().is_some_and(|key| !key.is_empty())
            || self
                .header
                .as_ref()
                .is_some_and(|header| !is_inert_raw_tcp_header(header))
            || self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DomainSocketSettingsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(
        default,
        rename = "abstract",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
            || self.padding.is_some_and(|padding| padding)
            || self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SockoptConfig {
    #[serde(
        default,
        rename = "tcpFastOpen",
        deserialize_with = "deserialize_bool_or_null"
    )]
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
    #[serde(
        default,
        rename = "tcpMptcp",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub tcp_mptcp: bool,
    #[serde(default, rename = "interface", skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(
        default,
        rename = "tcpNoDelay",
        deserialize_with = "deserialize_bool_or_null"
    )]
    pub tcp_no_delay: bool,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl SockoptConfig {
    fn has_unsupported_feature_with_dialer_proxy(&self, allow_dialer_proxy: bool) -> bool {
        self.mark.is_some_and(|mark| mark != 0)
            || self
                .tproxy
                .as_deref()
                .is_some_and(|tproxy| !matches!(tproxy, "" | "off"))
            || self.domain_strategy.as_deref().is_some_and(|strategy| {
                !matches!(
                    strategy,
                    "" | "AsIs"
                        | "IPIfNonMatch"
                        | "UseIP"
                        | "UseIPv4"
                        | "UseIPv6"
                        | "UseIPv4v6"
                        | "UseIPv6v4"
                )
            })
            || self
                .dialer_proxy
                .as_deref()
                .is_some_and(|proxy| !proxy.is_empty() && !allow_dialer_proxy)
            || self.tcp_mptcp
            || self
                .interface_name
                .as_deref()
                .is_some_and(|interface| !interface.is_empty())
            || self.extra.values().any(has_non_empty_value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RoutingConfig {
    #[serde(default, deserialize_with = "deserialize_routing_rule_vec_or_null")]
    pub rules: Vec<RoutingRuleConfig>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_routing_balancer_vec_or_null"
    )]
    pub balancers: Vec<RoutingBalancerConfig>,
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
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoutingConfig {
    fn unsupported_field(&self) -> Option<String> {
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RoutingBalancerConfig {
    #[serde(default, deserialize_with = "deserialize_string_or_null")]
    pub tag: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub selector: Vec<String>,
    #[serde(
        default,
        rename = "fallbackTag",
        skip_serializing_if = "Option::is_none"
    )]
    pub fallback_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<RoutingBalancerStrategyConfig>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoutingBalancerConfig {
    fn unsupported_field(&self) -> Option<String> {
        if self
            .strategy
            .as_ref()
            .is_some_and(RoutingBalancerStrategyConfig::has_unsupported_feature)
        {
            return Some("strategy".to_owned());
        }
        unsupported_non_empty_extra_field(&self.extra)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RoutingBalancerStrategyConfig {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub strategy_type: Option<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoutingBalancerStrategyConfig {
    fn has_unsupported_feature(&self) -> bool {
        !matches!(
            self.strategy_type.as_deref(),
            None | Some("") | Some("random") | Some("leastPing")
        ) || unsupported_non_empty_extra_field(&self.extra).is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoutingRuleConfig {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(
        default,
        rename = "inboundTag",
        alias = "inbound_tag",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub inbound_tag: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<RoutingPortMatcherConfig>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub domain: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub protocol: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_vec_or_null"
    )]
    pub user: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<Value>,
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
        unsupported_non_empty_extra_field(&self.extra)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self
            .rule_type
            .as_deref()
            .is_some_and(|rule_type| !matches!(rule_type, "" | "field"))
        {
            return Err(ConfigError::UnsupportedRoutingRuleField("type".to_owned()));
        }
        if let Some(port) = &self.port {
            port.validate()?;
        }
        if let Some(network) = &self.network {
            network.validate()?;
        }
        for domain in &self.domain {
            validate_routing_rule_domain_matcher(domain)?;
        }
        for ip in &self.ip {
            validate_routing_rule_ip_matcher(ip)?;
        }
        for source in &self.source {
            validate_routing_source_matcher(source)?;
        }
        if let Some(source_port) = &self.source_port {
            source_port.validate()?;
        }
        if self
            .protocol
            .iter()
            .any(|protocol| !matches!(protocol.as_str(), "" | "http" | "tls" | "quic"))
        {
            return Err(ConfigError::UnsupportedRoutingRuleField(
                "protocol".to_owned(),
            ));
        }
        if self.attrs.as_ref().is_some_and(unsupported_routing_attrs) {
            return Err(ConfigError::UnsupportedRoutingRuleField("attrs".to_owned()));
        }
        match (self.outbound_tag.as_ref(), self.balancer_tag.as_ref()) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::UnsupportedRoutingRuleField(
                    "balancerTag".to_owned(),
                ));
            }
            (None, None) => {
                return Err(ConfigError::UnsupportedRoutingRuleField(
                    "outboundTag".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn deserialize_bool_or_null<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<bool>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_u16_or_null<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<u16>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_string_or_null<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_string_vec_or_null<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_tls_certificate_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<TlsCertificateConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<TlsCertificateConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_inbound_vec_or_null<'de, D>(deserializer: D) -> Result<Vec<InboundConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<InboundConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_outbound_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<OutboundConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<OutboundConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_inbound_client_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<InboundClientConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<InboundClientConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_inbound_account_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<InboundAccountConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<InboundAccountConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_proxy_server_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<ProxyServerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<ProxyServerConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_routing_rule_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<RoutingRuleConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<RoutingRuleConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_routing_balancer_vec_or_null<'de, D>(
    deserializer: D,
) -> Result<Vec<RoutingBalancerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<RoutingBalancerConfig>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn validate_routing_domain_matcher(value: &str) -> Result<(), ConfigError> {
    match value {
        "" | "linear" | "mph" | "hybrid" => Ok(()),
        _ => Err(ConfigError::UnsupportedRoutingDomainMatcher(
            value.to_owned(),
        )),
    }
}

fn validate_routing_rule_domain_matcher(value: &str) -> Result<(), ConfigError> {
    let raw_value = value;
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if !raw_value.is_empty() && raw_value != raw_value.trim() {
        return Err(ConfigError::InvalidRoutingRuleDomainMatcher {
            value,
            reason: "malformed matcher payload".to_owned(),
        });
    }
    if value.is_empty() {
        return Err(ConfigError::InvalidRoutingRuleDomainMatcher {
            value,
            reason: "empty matcher".to_owned(),
        });
    }
    for prefix in ["full:", "domain:", "keyword:", "regexp:", "geosite:"] {
        if let Some(payload) = value.strip_prefix(prefix) {
            if payload.trim().is_empty() {
                return Err(ConfigError::InvalidRoutingRuleDomainMatcher {
                    value,
                    reason: "empty matcher".to_owned(),
                });
            }
            if payload != payload.trim() {
                return Err(ConfigError::InvalidRoutingRuleDomainMatcher {
                    value,
                    reason: "malformed matcher payload".to_owned(),
                });
            }
        }
    }
    if let Some(pattern) = value.strip_prefix("regexp:") {
        return Regex::new(pattern).map(|_| ()).map_err(|source| {
            ConfigError::InvalidRoutingRuleDomainMatcher {
                value,
                reason: source.to_string(),
            }
        });
    }
    if let Some(name) = value.strip_prefix("geosite:")
        && !matches!(name, "private" | "cn")
    {
        return Err(ConfigError::InvalidRoutingRuleDomainMatcher {
            value,
            reason: "unsupported geosite list".to_owned(),
        });
    }
    Ok(())
}

fn validate_routing_rule_ip_matcher(value: &str) -> Result<(), ConfigError> {
    if let Some(name) = value.strip_prefix("geoip:") {
        return match name {
            "private" | "cn" => Ok(()),
            _ => Err(ConfigError::InvalidRoutingRuleIpMatcher {
                value: value.to_owned(),
                reason: "unsupported geoip list".to_owned(),
            }),
        };
    }
    if value.contains('/') {
        return value.parse::<IpNet>().map(|_| ()).map_err(|source| {
            ConfigError::InvalidRoutingRuleIpMatcher {
                value: value.to_owned(),
                reason: source.to_string(),
            }
        });
    }

    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|source| ConfigError::InvalidRoutingRuleIpMatcher {
            value: value.to_owned(),
            reason: source.to_string(),
        })
}

fn validate_routing_source_matcher(value: &str) -> Result<(), ConfigError> {
    if let Some(name) = value.strip_prefix("geoip:") {
        return match name {
            "private" | "cn" => Ok(()),
            _ => Err(ConfigError::InvalidRoutingSourceMatcher {
                value: value.to_owned(),
                reason: "unsupported geoip list".to_owned(),
            }),
        };
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingNetwork {
    Tcp,
    Udp,
    Quic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingNetworkMatcherConfig(String);

impl RoutingNetworkMatcherConfig {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn networks(&self) -> Result<Vec<RoutingNetwork>, ConfigError> {
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

fn parse_routing_networks(value: &str) -> Result<Vec<RoutingNetwork>, ConfigError> {
    let networks = value
        .split(',')
        .map(str::trim)
        .filter(|network| !network.is_empty())
        .map(parse_routing_network)
        .collect::<Result<Vec<_>, _>>()?;
    if networks.is_empty() {
        parse_routing_network("").map(|network| vec![network])
    } else {
        Ok(networks)
    }
}

fn parse_routing_network(value: &str) -> Result<RoutingNetwork, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(RoutingNetwork::Tcp),
        "udp" => Ok(RoutingNetwork::Udp),
        "quic" => Ok(RoutingNetwork::Quic),
        _ => Err(ConfigError::InvalidRoutingNetworkMatcher {
            value: value.to_owned(),
            reason: "expected tcp, udp, or quic".to_owned(),
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
    let ranges = value
        .split(',')
        .map(str::trim)
        .filter(|range| !range.is_empty())
        .map(parse_routing_port_range)
        .collect::<Result<Vec<_>, _>>()?;
    if ranges.is_empty() {
        parse_routing_port_range("").map(|range| vec![range])
    } else {
        Ok(ranges)
    }
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
    fn accepts_shadowsocks_inbound_network_modes() {
        for network in ["tcp", "udp", "tcp,udp", "tcp, udp"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"ss-in","listen":"127.0.0.1","port":1080,"protocol":"shadowsocks","settings":{{"method":"chacha20-ietf-poly1305","password":"secret","network":"{network}"}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0]
                    .settings
                    .as_ref()
                    .unwrap()
                    .network
                    .as_deref(),
                Some(network)
            );
        }
    }

    #[test]
    fn accepts_shadowsocks_inbound_network_modes_with_empty_segments() {
        for network in ["tcp,", ",udp", "tcp,,udp", "tcp, , udp"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"ss-in","listen":"127.0.0.1","port":1080,"protocol":"shadowsocks","settings":{{"method":"chacha20-ietf-poly1305","password":"secret","network":"{network}"}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_empty_inbound_network_settings() {
        for (protocol, settings) in [
            (
                "shadowsocks",
                r#"{"method":"chacha20-ietf-poly1305","password":"secret","network":""}"#,
            ),
            ("socks", r#"{"network":""}"#),
            ("http", r#"{"network":""}"#),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_dokodemo_door_supported_network_settings() {
        for network in ["tcp", "udp", "tcp,udp", "tcp, udp"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"door","port":1080,"protocol":"dokodemo-door","settings":{{"address":"127.0.0.1","port":80,"network":"{network}"}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0]
                    .settings
                    .as_ref()
                    .unwrap()
                    .network
                    .as_deref(),
                Some(network)
            );
        }
    }

    #[test]
    fn rejects_unsupported_inbound_network_settings() {
        for (protocol, settings) in [
            (
                "shadowsocks",
                r#"{"method":"chacha20-ietf-poly1305","password":"secret","network":"quic"}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"network":"tcp,tcp"}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"network":"tcp, tcp"}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"network":"tcp,"}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"network":",udp"}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"network":"tcp,,udp"}"#,
            ),
            ("socks", r#"{"network":"tcp"}"#),
            ("http", r#"{"network":"tcp"}"#),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "network"
            ));
        }
    }

    #[test]
    fn accepts_inert_inbound_credential_settings() {
        for settings in [
            r#"{"method":""}"#,
            r#"{"password":""}"#,
            r#"{"method":"","password":""}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_inbound_credential_settings() {
        for (settings, field) in [
            (r#"{"method":"chacha20-ietf-poly1305"}"#, "method"),
            (r#"{"password":"secret"}"#, "password"),
            (
                r#"{"method":"chacha20-ietf-poly1305","password":"secret"}"#,
                "method",
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(actual)) if actual == field
            ));
        }
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
        for security in [
            "",
            r#", "security": "none""#,
            r#", "security": "aes-128-gcm""#,
            r#", "security": "chacha20-poly1305""#,
            r#", "security": "auto""#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"vmess-in","listen":"127.0.0.1","port":1080,"protocol":"vmess","settings":{{"clients":[{{"id":"01234567-89ab-cdef-0123-456789abcdef"}}]}}}}],
                  "outbounds": [{{"tag":"vmess-out","protocol":"vmess","settings":{{"servers":[{{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef"{security}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vmess);
            assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Vmess);
        }
    }

    #[test]
    fn accepts_vmess_zero_alter_id() {
        let json = r#"
        {
          "inbounds": [{"tag":"vmess-in","listen":"127.0.0.1","port":1080,"protocol":"vmess","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef","alterId":0}]}}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","alterId":0}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_non_zero_vmess_inbound_alter_id() {
        let json = r#"
        {
          "inbounds": [{"tag":"vmess-in","listen":"127.0.0.1","port":1080,"protocol":"vmess","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef","alterId":1}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundClientField(field)) if field == "alterId"
        ));
    }

    #[test]
    fn rejects_non_zero_vmess_outbound_alter_id() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","alterId":1}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "alterId"
        ));
    }

    #[test]
    fn parses_valid_vless_inbound_and_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","listen":"127.0.0.1","port":1080,"protocol":"vless","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}],
          "outbounds": [{"tag":"vless-out","protocol":"vless","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vless);
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Vless);
    }

    #[test]
    fn accepts_empty_proxy_server_flow() {
        for protocol in ["vmess", "vless"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy-out","protocol":"{protocol}","settings":{{"servers":[{{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","flow":""}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_proxy_server_email() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","email":"alice@example.com"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "email"
        ));
    }

    #[test]
    fn rejects_non_empty_proxy_server_flow() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vless-out","protocol":"vless","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","flow":"xtls-rprx-vision"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "flow"
        ));
    }

    #[test]
    fn accepts_vless_proxy_server_none_encryption() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vless-out","protocol":"vless","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","encryption":"none"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_vless_proxy_server_non_none_encryption() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vless-out","protocol":"vless","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","encryption":"aes-128-gcm"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "encryption"
        ));
    }

    #[test]
    fn parses_valid_trojan_inbound_and_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","listen":"127.0.0.1","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret"}]}}],
          "outbounds": [{"tag":"trojan-out","protocol":"trojan","settings":{"servers":[{"address":"127.0.0.1","port":10086,"password":"secret"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Trojan);
        assert_eq!(config.outbounds[0].protocol, OutboundProtocol::Trojan);
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
    fn rejects_unsupported_vmess_security() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"vmess-out","protocol":"vmess","settings":{"servers":[{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef","security":"zero"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedVmessSecurity(security)) if security == "zero"
        ));
    }

    #[test]
    fn rejects_non_proxy_outbound_servers() {
        for protocol in ["freedom", "blackhole"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{{"address":"127.0.0.1","port":1081}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "servers"
            ));
        }
    }

    #[test]
    fn accepts_nullable_non_proxy_outbound_servers_default() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"servers":null}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.outbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .servers
                .is_empty()
        );
    }

    #[test]
    fn rejects_multiple_proxy_outbound_servers() {
        for (protocol, first_server, second_server) in [
            (
                "dns",
                r#"{"address":"127.0.0.1","port":5353}"#,
                r#"{"address":"127.0.0.2","port":5354}"#,
            ),
            (
                "socks",
                r#"{"address":"127.0.0.1","port":1080}"#,
                r#"{"address":"127.0.0.2","port":1081}"#,
            ),
            (
                "http",
                r#"{"address":"127.0.0.1","port":8080}"#,
                r#"{"address":"127.0.0.2","port":8081}"#,
            ),
            (
                "shadowsocks",
                r#"{"address":"127.0.0.1","port":8388,"method":"chacha20-ietf-poly1305","password":"secret"}"#,
                r#"{"address":"127.0.0.2","port":8389,"method":"chacha20-ietf-poly1305","password":"secret"}"#,
            ),
            (
                "vmess",
                r#"{"address":"127.0.0.1","port":10086,"id":"01234567-89ab-cdef-0123-456789abcdef"}"#,
                r#"{"address":"127.0.0.2","port":10087,"id":"01234567-89ab-cdef-0123-456789abcdef"}"#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{first_server},{second_server}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "servers"
            ));
        }
    }

    #[test]
    fn parses_inert_inbound_allocation_settings() {
        for allocate in [
            r#"{}"#,
            r#"{"strategy":""}"#,
            r#"{"strategy":"always"}"#,
            r#"{"refresh":0}"#,
            r#"{"refresh":5}"#,
            r#"{"concurrency":0}"#,
            r#"{"concurrency":3}"#,
            r#"{"strategy":"always","refresh":5,"concurrency":3}"#,
            r#"{"unknownAllocationOption":null}"#,
            r#"{"unknownAllocationOption":{}}"#,
            r#"{"unknownAllocationOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","allocate":{allocate}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(config.inbounds[0].allocate.is_some());
        }
    }

    #[test]
    fn rejects_unsupported_inbound_allocation_settings() {
        for allocate in [
            r#"{"strategy":"random"}"#,
            r#"{"strategy":"external"}"#,
            r#"{"refresh":10}"#,
            r#"{"concurrency":4}"#,
            r#"{"unknownAllocationOption":true}"#,
            r#"{"unknownAllocationOption":0}"#,
            r#"{"unknownAllocationOption":""}"#,
            r#"{"unknownAllocationOption":{"key":"value"}}"#,
            r#"{"unknownAllocationOption":[true]}"#,
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
    fn accepts_null_unknown_inbound_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","unknownInboundOption":{unknown_value}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(
                config.inbounds[0]
                    .extra
                    .contains_key("unknownInboundOption")
            );
        }
    }

    #[test]
    fn rejects_unknown_inbound_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","unknownInboundOption":{unknown_value}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field))
                    if field == "unknownInboundOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_inbound_settings_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{{"unknownInboundSetting":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let settings = config.inbounds[0].settings.as_ref().unwrap();
            assert!(settings.extra.contains_key("unknownInboundSetting"));
        }
    }

    #[test]
    fn rejects_active_unknown_inbound_settings_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{{"unknownInboundSetting":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field))
                    if field == "unknownInboundSetting"
            ));
        }
    }

    #[test]
    fn accepts_socks_inbound_auth_modes() {
        let noauth = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"auth":"noauth"}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(noauth).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .auth
                .as_deref(),
            Some("noauth")
        );

        let password = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"alice","pass":"secret"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(password).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .auth
                .as_deref(),
            Some("password")
        );
    }

    #[test]
    fn accepts_inert_inbound_auth() {
        for protocol in ["http", "socks"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{{"auth":""}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0]
                    .settings
                    .as_ref()
                    .unwrap()
                    .auth
                    .as_deref(),
                Some("")
            );
        }
    }

    #[test]
    fn rejects_socks_inbound_auth_modes_without_matching_runtime_behavior() {
        for settings in [
            r#"{"auth":"password"}"#,
            r#"{"auth":"noauth","accounts":[{"user":"alice","pass":"secret"}]}"#,
            r#"{"auth":"unknown"}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "auth"
            ));
        }
    }

    #[test]
    fn accepts_http_inbound_password_auth_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http","settings":{"auth":"password","accounts":[{"user":"alice","pass":"secret"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let settings = config.inbounds[0].settings.as_ref().unwrap();
        assert_eq!(settings.auth.as_deref(), Some("password"));
        assert_eq!(settings.accounts[0].user, "alice");
    }

    #[test]
    fn accepts_http_inbound_noauth_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http","settings":{"auth":"noauth"}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let settings = config.inbounds[0].settings.as_ref().unwrap();
        assert_eq!(settings.auth.as_deref(), Some("noauth"));
        assert!(settings.accounts.is_empty());
    }

    #[test]
    fn accepts_nullable_inbound_settings_lists() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http","settings":{"auth":"noauth","accounts":null,"clients":null}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let settings = config.inbounds[0].settings.as_ref().unwrap();
        assert!(settings.accounts.is_empty());
        assert!(settings.clients.is_empty());
    }

    #[test]
    fn rejects_http_inbound_noauth_with_accounts() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http","settings":{"auth":"noauth","accounts":[{"user":"alice","pass":"secret"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "auth"
        ));
    }

    #[test]
    fn accepts_socks_inbound_udp_enabled() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"udp":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0].settings.as_ref().unwrap().udp,
            Some(true)
        );
    }

    #[test]
    fn accepts_disabled_inbound_udp() {
        for protocol in ["http", "socks"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{{"udp":false}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0].settings.as_ref().unwrap().udp,
                Some(false)
            );
        }
    }

    #[test]
    fn rejects_unsupported_inbound_udp_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"test-in","port":1080,"protocol":"http","settings":{"udp":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "udp"
        ));
    }

    #[test]
    fn accepts_inert_inbound_ip() {
        for protocol in ["http", "socks"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{{"ip":""}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0].settings.as_ref().unwrap().ip.as_deref(),
                Some("")
            );
        }
    }

    #[test]
    fn rejects_unsupported_inbound_ip_settings() {
        for (protocol, settings) in [
            ("socks", r#"{"ip":"127.0.0.1"}"#),
            ("http", r#"{"ip":"127.0.0.1"}"#),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "ip"
            ));
        }
    }

    #[test]
    fn accepts_inert_inbound_allow_transparent() {
        for protocol in ["http", "socks"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{{"allowTransparent":false}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0]
                    .settings
                    .as_ref()
                    .unwrap()
                    .allow_transparent,
                Some(false)
            );
        }
    }

    #[test]
    fn rejects_unsupported_allow_transparent_settings() {
        for (protocol, settings) in [
            ("http", r#"{"allowTransparent":true}"#),
            ("socks", r#"{"allowTransparent":true}"#),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "allowTransparent"
            ));
        }
    }

    #[test]
    fn accepts_inert_inbound_timeout() {
        for protocol in ["http", "socks"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{{"timeout":0}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.inbounds[0].settings.as_ref().unwrap().timeout,
                Some(0)
            );
        }
    }

    #[test]
    fn rejects_unsupported_inbound_timeout_settings() {
        for (protocol, settings) in [("http", r#"{"timeout":1}"#), ("socks", r#"{"timeout":1}"#)] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "timeout"
            ));
        }
    }

    #[test]
    fn accepts_inert_inbound_user_level_zero() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"userLevel":0}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0].settings.as_ref().unwrap().user_level,
            Some(0)
        );
    }

    #[test]
    fn rejects_active_inbound_user_level() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","settings":{"userLevel":1}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "userLevel"
        ));
    }

    #[test]
    fn accepts_protocol_owned_inbound_principals() {
        for (protocol, settings) in [
            (
                "socks",
                r#"{"accounts":[{"user":"alice","pass":"secret"}]}"#,
            ),
            ("http", r#"{"accounts":[{"user":"alice","pass":"secret"}]}"#),
            ("trojan", r#"{"clients":[{"password":"secret"}]}"#),
            (
                "vless",
                r#"{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}"#,
            ),
            (
                "vmess",
                r#"{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}"#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unowned_inbound_principals() {
        for (protocol, settings, field) in [
            (
                "shadowsocks",
                r#"{"method":"chacha20-ietf-poly1305","password":"secret","accounts":[{"user":"alice","pass":"secret"}]}"#,
                "accounts",
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"accounts":[{"user":"alice","pass":"secret"}]}"#,
                "accounts",
            ),
            ("socks", r#"{"clients":[{"password":"secret"}]}"#, "clients"),
            ("http", r#"{"clients":[{"password":"secret"}]}"#, "clients"),
            (
                "shadowsocks",
                r#"{"method":"chacha20-ietf-poly1305","password":"secret","clients":[{"password":"secret"}]}"#,
                "clients",
            ),
            (
                "dokodemo-door",
                r#"{"address":"127.0.0.1","port":80,"clients":[{"password":"secret"}]}"#,
                "clients",
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn rejects_non_vless_inbound_decryption() {
        for (protocol, settings) in [
            (
                "trojan",
                r#"{"decryption":"none","clients":[{"password":"secret"}]}"#,
            ),
            (
                "vmess",
                r#"{"decryption":"none","clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}"#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"test-in","port":1080,"protocol":"{protocol}","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(field)) if field == "decryption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_inbound_account_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{{"accounts":[{{"user":"alice","pass":"secret","unknownAccountOption":{unknown_value}}}]}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let account = &config.inbounds[0].settings.as_ref().unwrap().accounts[0];
            assert!(account.extra.contains_key("unknownAccountOption"));
        }
    }

    #[test]
    fn rejects_active_unknown_inbound_account_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{{"accounts":[{{"user":"alice","pass":"secret","unknownAccountOption":{unknown_value}}}]}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundAccountField(field))
                    if field == "unknownAccountOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_inbound_client_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{{"clients":[{{"password":"secret","unknownClientOption":{unknown_value}}}]}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let client = &config.inbounds[0].settings.as_ref().unwrap().clients[0];
            assert!(client.extra.contains_key("unknownClientOption"));
        }
    }

    #[test]
    fn rejects_active_unknown_inbound_client_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{{"clients":[{{"password":"secret","unknownClientOption":{unknown_value}}}]}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundClientField(field))
                    if field == "unknownClientOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_inbound_client_metadata() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret","email":"alice@example.com","level":0}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let client = &config.inbounds[0].settings.as_ref().unwrap().clients[0];
        assert_eq!(client.email.as_deref(), Some("alice@example.com"));
        assert_eq!(client.level, Some(0));
    }

    #[test]
    fn rejects_active_inbound_client_level() {
        let json = r#"
        {
          "inbounds": [{"tag":"trojan-in","port":1080,"protocol":"trojan","settings":{"clients":[{"password":"secret","email":"alice@example.com","level":1}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundClientField(field)) if field == "level"
        ));
    }

    #[test]
    fn rejects_unowned_inbound_client_fields() {
        for (protocol, client, field) in [
            (
                "trojan",
                r#""password":"secret","id":"01234567-89ab-cdef-0123-456789abcdef""#,
                "id",
            ),
            (
                "vless",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef","password":"secret""#,
                "password",
            ),
            (
                "vmess",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef","password":"secret""#,
                "password",
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"proxy-in","port":1080,"protocol":"{protocol}","settings":{{"clients":[{{{client}}}],"decryption":"none"}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundClientField(rejected_field)) if rejected_field == field
            ));
        }
    }

    #[test]
    fn accepts_nullable_log_level_default() {
        let json = r#"
        {
          "log": {"level": null},
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.log.level, "info");
    }

    #[test]
    fn accepts_inert_log_dns_log_false() {
        for dns_log in ["false", "null"] {
            let json = format!(
                r#"{{
                  "log": {{"level":"warning","dnsLog":{dns_log}}},
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(config.log.level, "warning");
            assert!(!config.log.dns_log);
        }
    }

    #[test]
    fn accepts_disabled_log_outputs() {
        let json = r#"
        {
          "log": {"access":"none","error":"none"},
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.log.access.as_deref(), Some("none"));
        assert_eq!(config.log.error.as_deref(), Some("none"));
    }

    #[test]
    fn accepts_inert_unknown_log_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "log": {{"level":"warning","unknownLogOption":{unknown_value}}},
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(config.log.level, "warning");
            assert!(config.log.extra.contains_key("unknownLogOption"));
        }
    }

    #[test]
    fn rejects_active_log_dns_log() {
        let json = r#"
        {
          "log": {"dnsLog":true},
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedLogField(field)) if field == "dnsLog"
        ));
    }

    #[test]
    fn accepts_empty_log_outputs() {
        let json = r#"
        {
          "log": {"access":"","error":""},
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.log.access.as_deref(), Some(""));
        assert_eq!(config.log.error.as_deref(), Some(""));
    }

    #[test]
    fn rejects_active_log_outputs() {
        for (field, value) in [("access", "/tmp/access.log"), ("error", "/tmp/error.log")] {
            let json = format!(
                r#"{{
                  "log": {{"{field}":"{value}"}},
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedLogField(rejected)) if rejected == field
            ));
        }
    }

    #[test]
    fn rejects_active_unknown_log_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "log": {{"unknownLogOption":{unknown_value}}},
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedLogField(field)) if field == "unknownLogOption"
            ));
        }
    }

    #[test]
    fn merged_active_log_dns_log_is_rejected() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "log":{"dnsLog":true}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedLogField(field)) if field == "dnsLog"
        ));
    }

    #[test]
    fn merged_active_log_dns_log_cannot_be_cleared_by_false() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "log":{"dnsLog":true},
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "log":{"dnsLog":false}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedLogField(field)) if field == "dnsLog"
        ));
    }

    #[test]
    fn merged_active_log_outputs_cannot_be_cleared_by_disabled_values() {
        for disabled_value in ["", "none"] {
            for field in ["access", "error"] {
                let mut first: RootConfig = serde_json::from_str(&format!(
                    r#"{{
                      "log":{{"{field}":"/tmp/{field}.log"}},
                      "inbounds":[{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                      "outbounds":[{{"tag":"direct","protocol":"freedom"}}]
                    }}"#
                ))
                .unwrap();
                let second: RootConfig = serde_json::from_str(&format!(
                    r#"{{
                      "log":{{"{field}":"{disabled_value}"}}
                    }}"#
                ))
                .unwrap();

                first.merge(second);
                assert!(matches!(
                    first.validate(),
                    Err(ConfigError::UnsupportedLogField(rejected)) if rejected == field
                ));
            }
        }
    }

    #[test]
    fn merged_disabled_log_outputs_override_absent_values() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "log":{"access":"none","error":"none"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.log.access.as_deref(), Some("none"));
        assert_eq!(first.log.error.as_deref(), Some("none"));
    }

    #[test]
    fn merged_inert_unknown_log_fields_are_rejected_when_overridden_by_active_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "log":{{"unknownLogOption":{unknown_value}}},
                  "inbounds":[{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds":[{{"tag":"direct","protocol":"freedom"}}]
                }}"#,
            ))
            .unwrap();
            let second: RootConfig = serde_json::from_str(
                r#"{
                  "log":{"unknownLogOption":true}
                }"#,
            )
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedLogField(field)) if field == "unknownLogOption"
            ));
        }
    }

    #[test]
    fn merged_active_unknown_log_fields_cannot_be_cleared_by_inert_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "log":{"unknownLogOption":true},
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}]
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "log":{{"unknownLogOption":{unknown_value}}}
                }}"#,
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedLogField(field)) if field == "unknownLogOption"
            ));
        }
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
    fn accepts_inert_api_settings() {
        for api in [
            r#"{"tag":"","services":[]}"#,
            r#"{"tag":"","services":null}"#,
            r#"{"unknownApiOption":null}"#,
            r#"{"unknownApiOption":{}}"#,
            r#"{"unknownApiOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "api": {api}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_api_settings() {
        for api in [
            r#"{"tag":"api","services":[]}"#,
            r#"{"tag":"","services":["StatsService"]}"#,
            r#"{"tag":"api","services":["StatsService"]}"#,
            r#"{"unknownApiOption":true}"#,
            r#"{"unknownApiOption":{"key":"value"}}"#,
            r#"{"unknownApiOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "api": {api}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedApiFeature)
            ));
        }
    }

    #[test]
    fn accepts_empty_known_top_level_sections() {
        for field in [
            "api",
            "browserForwarder",
            "transport",
            "reverse",
            "geodata",
            "dns",
            "policy",
            "stats",
            "observatory",
            "burstObservatory",
            "fakedns",
            "metrics",
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "{field}": {{}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn merged_active_known_top_level_sections_cannot_be_cleared_by_empty_values() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "api":{"services":["StatsService"]}
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "api":{}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedApiFeature)
        ));
    }

    #[test]
    fn merged_active_api_cannot_be_cleared_by_inert_unknown_fields() {
        for api in [
            r#"{"unknownApiOption":null}"#,
            r#"{"unknownApiOption":{}}"#,
            r#"{"unknownApiOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "api":{"services":["StatsService"]}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "api": {api}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedApiFeature)
            ));
        }
    }

    #[test]
    fn merged_active_known_top_level_sections_override_empty_values() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "api":{}
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "api":{"services":["StatsService"]}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedApiFeature)
        ));
    }

    #[test]
    fn merged_active_top_level_dns_cannot_be_cleared_by_inert_values() {
        for dns in [
            r#"{"servers":[],"hosts":{}}"#,
            r#"{"servers":[],"hosts":{},"clientIp":"","queryStrategy":"UseIP","disableCache":false,"serveStale":false,"serveExpiredTTL":0,"disableFallback":false,"disableFallbackIfMatch":false,"enableParallelQuery":false,"useSystemHosts":false,"tag":""}"#,
            r#"{"servers":[],"hosts":{},"clientIP":""}"#,
            r#"{"servers":[],"hosts":{},"queryStrategy":""}"#,
            r#"{"unknownDnsOption":null}"#,
            r#"{"unknownDnsOption":{}}"#,
            r#"{"unknownDnsOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "dns":{"servers":["1.1.1.1"]}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "dns": {dns}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            first.validate().unwrap();
            assert_eq!(
                first.dns.as_ref().and_then(|dns| dns.get("servers")),
                Some(&serde_json::json!(["1.1.1.1"]))
            );
        }
    }

    #[test]
    fn accepts_inert_browser_forwarder_settings() {
        for browser_forwarder in [
            "null",
            "{}",
            r#"{"unknownBrowserForwarderOption":null}"#,
            r#"{"unknownBrowserForwarderOption":{}}"#,
            r#"{"unknownBrowserForwarderOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "browserForwarder": {browser_forwarder}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_browser_forwarder_settings() {
        for browser_forwarder in [
            r#"{"listenAddr":"127.0.0.1","listenPort":8080}"#,
            r#"{"unknownBrowserForwarderOption":true}"#,
            r#"{"unknownBrowserForwarderOption":{"key":"value"}}"#,
            r#"{"unknownBrowserForwarderOption":[true]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "browserForwarder": {browser_forwarder}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedBrowserForwarderFeature)
            ));
        }
    }

    #[test]
    fn merged_active_browser_forwarder_cannot_be_cleared_by_inert_values() {
        for browser_forwarder in [
            "null",
            "{}",
            r#"{"unknownBrowserForwarderOption":null}"#,
            r#"{"unknownBrowserForwarderOption":{}}"#,
            r#"{"unknownBrowserForwarderOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "browserForwarder":{"listenAddr":"127.0.0.1","listenPort":8080}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "browserForwarder": {browser_forwarder}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedBrowserForwarderFeature)
            ));
        }
    }

    #[test]
    fn merged_active_top_level_transport_cannot_be_cleared_by_inert_values() {
        for transport in [
            "null",
            "{}",
            r#"{"tcpSettings":null,"kcpSettings":null}"#,
            r#"{"unknownTransportOption":null}"#,
            r#"{"unknownTransportOption":{}}"#,
            r#"{"unknownTransportOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "transport":{"tcpSettings":{"header":{"type":"http"}}},
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}]
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "transport": {transport}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedTopLevelTransportFeature)
            ));
        }
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
    fn accepts_inert_top_level_transport_settings() {
        for transport in [
            r#"{"tcpSettings": null, "kcpSettings": null, "unknownTransportOption": null}"#,
            r#"{"tcpSettings": {}, "kcpSettings": {}, "unknownTransportOption": null}"#,
            r#"{"tcpSettings": null, "unknownTransportOption": {}}"#,
            r#"{"tcpSettings": null, "unknownTransportOption": []}"#,
            r#"{"tcpSettings": {"acceptProxyProtocol":false,"header":{"type":"none"},"unknownTcpOption":null}, "unknownTransportOption": null}"#,
            r#"{"tcpSettings": {"acceptProxyProtocol":null}, "unknownTransportOption": null}"#,
            r#"{"tcpSettings": {"unknownTcpOption":{}}, "unknownTransportOption": null}"#,
            r#"{"tcpSettings": {"unknownTcpOption":[]}, "unknownTransportOption": null}"#,
            r#"{"kcpSettings": {"mtu":0,"tti":0,"uplinkCapacity":0,"downlinkCapacity":0,"congestion":false,"readBufferSize":0,"writeBufferSize":0,"header":{"type":"none"},"seed":"","unknownKcpOption":null}, "unknownTransportOption": null}"#,
            r#"{"kcpSettings": {"mtu":1350,"tti":50,"uplinkCapacity":5,"downlinkCapacity":20}, "unknownTransportOption": null}"#,
            r#"{"kcpSettings": {"cwndMultiplier":1,"maxSendingWindow":2097152}, "unknownTransportOption": null}"#,
            r#"{"kcpSettings": {"congestion":null}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": null, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {"header":{"type":"none"}}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {"acceptProxyProtocol":false,"header":{"type":"none"},"unknownRawOption":null}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {"acceptProxyProtocol":null}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {"unknownRawOption":{}}, "unknownTransportOption": null}"#,
            r#"{"rawSettings": {"unknownRawOption":[]}, "unknownTransportOption": null}"#,
            r#"{"quicSettings": {"security":"none","key":"","header":{"type":"none"}}, "unknownTransportOption": null}"#,
            r#"{"quicSettings": {"security":null,"key":null,"header":null}, "unknownTransportOption": null}"#,
            r#"{"grpcSettings": {"serviceName":"","authority":"","multiMode":false,"idle_timeout":0,"health_check_timeout":0,"permit_without_stream":false,"initial_windows_size":0,"noGRPCHeader":false,"unknownGrpcOption":null}, "unknownTransportOption": null}"#,
            r#"{"grpcSettings": {"serviceName":null,"authority":null}, "unknownTransportOption": null}"#,
            r#"{"grpcSettings": {"multiMode":null,"permit_without_stream":null,"noGRPCHeader":null}, "unknownTransportOption": null}"#,
            r#"{"grpcSettings": {"user_agent":""}, "unknownTransportOption": null}"#,
            r#"{"wsSettings": {"path":"","host":"","headers":{"Host":[]},"acceptProxyProtocol":false,"unknownWsOption":null}, "unknownTransportOption": null}"#,
            r#"{"wsSettings": {"path":"","host":"","headers":{"Host":""},"acceptProxyProtocol":false,"unknownWsOption":null}, "unknownTransportOption": null}"#,
            r#"{"wsSettings": {"path":null,"host":null}, "unknownTransportOption": null}"#,
            r#"{"wsSettings": {"acceptProxyProtocol":null}, "unknownTransportOption": null}"#,
            r#"{"httpupgradeSettings": {"host":"","path":"","headers":{"Host":[]},"acceptProxyProtocol":false,"unknownHttpUpgradeOption":null}, "unknownTransportOption": null}"#,
            r#"{"httpupgradeSettings": {"host":"","path":"","headers":{"Host":""},"acceptProxyProtocol":false,"unknownHttpUpgradeOption":null}, "unknownTransportOption": null}"#,
            r#"{"httpupgradeSettings": {"host":null,"path":null}, "unknownTransportOption": null}"#,
            r#"{"httpupgradeSettings": {"acceptProxyProtocol":null}, "unknownTransportOption": null}"#,
            r#"{"httpSettings": {"host":[],"path":"","method":"","headers":{"Host":[]},"read_idle_timeout":0,"health_check_timeout":0,"with_trailers":false,"unknownHttpOption":null}, "unknownTransportOption": null}"#,
            r#"{"httpSettings": {"host":[],"path":"","method":"","headers":{"Host":""},"read_idle_timeout":0,"health_check_timeout":0,"with_trailers":false,"unknownHttpOption":null}, "unknownTransportOption": null}"#,
            r#"{"httpSettings": {"path":null,"method":null,"headers":null}, "unknownTransportOption": null}"#,
            r#"{"httpSettings": {"host":""}, "unknownTransportOption": null}"#,
            r#"{"httpSettings": {"with_trailers":null}, "unknownTransportOption": null}"#,
            r#"{"dsSettings": {"path":"","abstract":false,"padding":false,"unknownDomainSocketOption":null}, "unknownTransportOption": null}"#,
            r#"{"dsSettings": {"path":null}, "unknownTransportOption": null}"#,
            r#"{"dsSettings": {"abstract":null,"padding":null}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","headers":{"Host":[]},"extra":{},"unknownXhttpOption":null}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","headers":{"Host":""},"extra":{},"unknownXhttpOption":null}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":null,"host":null,"mode":null}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","xPaddingKey":"x_padding","xPaddingHeader":"X-Padding"}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","xPaddingPlacement":"queryInHeader","xPaddingMethod":"repeat-x"}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","xPaddingKey":null,"xPaddingHeader":null,"xPaddingPlacement":null,"xPaddingMethod":null}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","uplinkHTTPMethod":"POST"}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","uplinkHTTPMethod":""}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","sessionPlacement":"path","seqPlacement":"path"}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","sessionPlacement":"","seqPlacement":""}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","uplinkDataPlacement":"auto"}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","uplinkDataPlacement":""}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","noSSEHeader":false}, "unknownTransportOption": null}"#,
            r#"{"xhttpSettings": {"path":"","host":"","mode":"auto","noSSEHeader":null}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":"","host":"","mode":"auto","headers":{"Host":[]},"scMaxConcurrentPosts":null,"scMaxBufferedPosts":null,"scMaxEachPostBytes":null,"scMinPostsIntervalMs":null,"xPaddingBytes":null,"xmux":{},"extra":{},"unknownSplitHttpOption":null}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"scMaxBufferedPosts":30}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"scMinPostsIntervalMs":30}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"scMinPostsIntervalMs":"30"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"scMaxEachPostBytes":1000000}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"scMaxEachPostBytes":"1000000"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"uplinkHTTPMethod":"POST"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"sessionPlacement":"path","seqPlacement":"path"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"uplinkDataPlacement":"auto"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"noGRPCHeader":false}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"noGRPCHeader":null}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"xPaddingKey":"x_padding","xPaddingHeader":"X-Padding"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"xPaddingPlacement":"queryInHeader","xPaddingMethod":"repeat-x"}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"xPaddingKey":null,"xPaddingHeader":null,"xPaddingPlacement":null,"xPaddingMethod":null}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"xmux":null}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null,"xmux":{"maxConcurrency":{"from":0,"to":0},"maxConnections":{"from":0,"to":0},"cMaxReuseTimes":{"from":0,"to":0},"hMaxRequestTimes":{"from":0,"to":0},"hMaxReusableSecs":{"from":0,"to":0},"hKeepAlivePeriod":0}}, "unknownTransportOption": null}"#,
            r#"{"splithttpSettings": {"path":null,"host":null,"mode":null}, "unknownTransportOption": null}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "transport": {transport}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_inert_nested_unknown_top_level_transport_fields() {
        for transport in [
            r#"{"quicSettings":{"unknownQuicOption":{}}}"#,
            r#"{"grpcSettings":{"unknownGrpcOption":[]}}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "transport": {transport}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_top_level_transport_settings() {
        for transport in [
            r#"{"tcpSettings":{"header":{"type":"http"}}}"#,
            r#"{"tcpSettings":{"acceptProxyProtocol":true}}"#,
            r#"{"tcpSettings":{"unknownTcpOption":true}}"#,
            r#"{"tcpSettings":{"unknownTcpOption":{"key":"value"}}}"#,
            r#"{"tcpSettings":{"unknownTcpOption":[true]}}"#,
            r#"{"kcpSettings":{"mtu":1349}}"#,
            r#"{"kcpSettings":{"tti":49}}"#,
            r#"{"kcpSettings":{"uplinkCapacity":6}}"#,
            r#"{"kcpSettings":{"downlinkCapacity":21}}"#,
            r#"{"kcpSettings":{"cwndMultiplier":2}}"#,
            r#"{"kcpSettings":{"maxSendingWindow":2097151}}"#,
            r#"{"kcpSettings":{"congestion":true}}"#,
            r#"{"kcpSettings":{"readBufferSize":2}}"#,
            r#"{"kcpSettings":{"writeBufferSize":2}}"#,
            r#"{"kcpSettings":{"header":{"type":"srtp"}}}"#,
            r#"{"kcpSettings":{"seed":"secret"}}"#,
            r#"{"kcpSettings":{"unknownKcpOption":true}}"#,
            r#"{"rawSettings":{"acceptProxyProtocol":true}}"#,
            r#"{"rawSettings":{"header":{"type":"http"}}}"#,
            r#"{"rawSettings":{"unknownRawOption":true}}"#,
            r#"{"rawSettings":{"unknownRawOption":{"key":"value"}}}"#,
            r#"{"rawSettings":{"unknownRawOption":[true]}}"#,
            r#"{"quicSettings":{"security":"aes-128-gcm"}}"#,
            r#"{"quicSettings":{"key":"secret"}}"#,
            r#"{"quicSettings":{"header":{"type":"srtp"}}}"#,
            r#"{"quicSettings":{"unknownQuicOption":true}}"#,
            r#"{"quicSettings":{"unknownQuicOption":{"key":"value"}}}"#,
            r#"{"quicSettings":{"unknownQuicOption":[true]}}"#,
            r#"{"grpcSettings":{"serviceName":"svc"}}"#,
            r#"{"grpcSettings":{"authority":"example.com"}}"#,
            r#"{"grpcSettings":{"user_agent":"xrs"}}"#,
            r#"{"grpcSettings":{"user_agent":null}}"#,
            r#"{"grpcSettings":{"multiMode":true}}"#,
            r#"{"grpcSettings":{"idle_timeout":1}}"#,
            r#"{"grpcSettings":{"noGRPCHeader":true}}"#,
            r#"{"grpcSettings":{"unknownGrpcOption":{"key":"value"}}}"#,
            r#"{"grpcSettings":{"unknownGrpcOption":[true]}}"#,
            r#"{"wsSettings":{"path":"/ws"}}"#,
            r#"{"wsSettings":{"host":"example.com"}}"#,
            r#"{"wsSettings":{"headers":{"Host":"example.com"}}}"#,
            r#"{"wsSettings":{"acceptProxyProtocol":true}}"#,
            r#"{"wsSettings":{"unknownWsOption":{"key":"value"}}}"#,
            r#"{"wsSettings":{"unknownWsOption":[true]}}"#,
            r#"{"httpupgradeSettings":{"path":"/upgrade"}}"#,
            r#"{"httpupgradeSettings":{"host":"example.com"}}"#,
            r#"{"httpupgradeSettings":{"headers":{"Host":"example.com"}}}"#,
            r#"{"httpupgradeSettings":{"acceptProxyProtocol":true}}"#,
            r#"{"httpupgradeSettings":{"unknownHttpUpgradeOption":{"key":"value"}}}"#,
            r#"{"httpupgradeSettings":{"unknownHttpUpgradeOption":[true]}}"#,
            r#"{"httpSettings":{"host":["example.com"]}}"#,
            r#"{"httpSettings":{"path":"/h2"}}"#,
            r#"{"httpSettings":{"method":"GET"}}"#,
            r#"{"httpSettings":{"headers":{"Host":"example.com"}}}"#,
            r#"{"httpSettings":{"read_idle_timeout":1}}"#,
            r#"{"httpSettings":{"health_check_timeout":1}}"#,
            r#"{"httpSettings":{"with_trailers":true}}"#,
            r#"{"httpSettings":{"unknownHttpOption":{"key":"value"}}}"#,
            r#"{"httpSettings":{"unknownHttpOption":[true]}}"#,
            r#"{"dsSettings":{"path":"/tmp/xrs.sock"}}"#,
            r#"{"dsSettings":{"abstract":true}}"#,
            r#"{"dsSettings":{"padding":true}}"#,
            r#"{"dsSettings":{"unknownDomainSocketOption":{"key":"value"}}}"#,
            r#"{"dsSettings":{"unknownDomainSocketOption":[true]}}"#,
            r#"{"xhttpSettings":{"path":"/xhttp"}}"#,
            r#"{"xhttpSettings":{"host":"example.com"}}"#,
            r#"{"xhttpSettings":{"mode":"packet-up"}}"#,
            r#"{"xhttpSettings":{"headers":{"Host":"example.com"}}}"#,
            r#"{"xhttpSettings":{"xPaddingKey":"custom_padding"}}"#,
            r#"{"xhttpSettings":{"xPaddingHeader":"X-Custom-Padding"}}"#,
            r#"{"xhttpSettings":{"xPaddingPlacement":"query"}}"#,
            r#"{"xhttpSettings":{"xPaddingMethod":"random"}}"#,
            r#"{"xhttpSettings":{"uplinkHTTPMethod":"GET"}}"#,
            r#"{"xhttpSettings":{"sessionPlacement":"cookie"}}"#,
            r#"{"xhttpSettings":{"seqPlacement":"query"}}"#,
            r#"{"xhttpSettings":{"uplinkDataPlacement":"body"}}"#,
            r#"{"xhttpSettings":{"noSSEHeader":true}}"#,
            r#"{"xhttpSettings":{"extra":{"key":"value"}}}"#,
            r#"{"xhttpSettings":{"unknownXhttpOption":{"key":"value"}}}"#,
            r#"{"xhttpSettings":{"unknownXhttpOption":[true]}}"#,
            r#"{"splithttpSettings":{"path":"/split"}}"#,
            r#"{"splithttpSettings":{"host":"example.com"}}"#,
            r#"{"splithttpSettings":{"mode":"packet-up"}}"#,
            r#"{"splithttpSettings":{"headers":{"Host":"example.com"}}}"#,
            r#"{"splithttpSettings":{"scMaxConcurrentPosts":100}}"#,
            r#"{"splithttpSettings":{"scMaxBufferedPosts":31}}"#,
            r#"{"splithttpSettings":{"scMaxEachPostBytes":999999}}"#,
            r#"{"splithttpSettings":{"scMaxEachPostBytes":"999999"}}"#,
            r#"{"splithttpSettings":{"scMaxEachPostBytes":"1m"}}"#,
            r#"{"splithttpSettings":{"scMinPostsIntervalMs":10}}"#,
            r#"{"splithttpSettings":{"xPaddingBytes":"100-1000"}}"#,
            r#"{"splithttpSettings":{"uplinkHTTPMethod":"GET"}}"#,
            r#"{"splithttpSettings":{"sessionPlacement":"cookie"}}"#,
            r#"{"splithttpSettings":{"seqPlacement":"query"}}"#,
            r#"{"splithttpSettings":{"uplinkDataPlacement":"body"}}"#,
            r#"{"splithttpSettings":{"noGRPCHeader":true}}"#,
            r#"{"splithttpSettings":{"xPaddingKey":"custom_padding"}}"#,
            r#"{"splithttpSettings":{"xPaddingHeader":"X-Custom-Padding"}}"#,
            r#"{"splithttpSettings":{"xPaddingPlacement":"query"}}"#,
            r#"{"splithttpSettings":{"xPaddingMethod":"random"}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":1}}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":4}}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":{"from":1,"to":1}}}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":{}}}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":{"from":0}}}}"#,
            r#"{"splithttpSettings":{"xmux":{"maxConcurrency":{"to":0}}}}"#,
            r#"{"splithttpSettings":{"xmux":{"hKeepAlivePeriod":1}}}"#,
            r#"{"splithttpSettings":{"xmux":{"unknownXmuxOption":null}}}"#,
            r#"{"splithttpSettings":{"xmux":{"unknownXmuxOption":{}}}}"#,
            r#"{"splithttpSettings":{"xmux":{"unknownXmuxOption":[]}}}"#,
            r#"{"splithttpSettings":{"extra":{"key":"value"}}}"#,
            r#"{"splithttpSettings":{"unknownSplitHttpOption":true}}"#,
            r#"{"tcpSettings":null,"unknownTransportOption":true}"#,
            r#"{"tcpSettings":null,"unknownTransportOption":{"key":"value"}}"#,
            r#"{"tcpSettings":null,"unknownTransportOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "transport": {transport}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTopLevelTransportFeature)
            ));
        }
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
    fn accepts_inert_reverse_settings() {
        for reverse in [
            r#"{"bridges": [], "portals": [], "unknownReverseOption": null}"#,
            r#"{"bridges": null, "portals": null, "unknownReverseOption": null}"#,
            r#"{"unknownReverseOption":{}}"#,
            r#"{"unknownReverseOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "reverse": {reverse}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn merged_active_reverse_cannot_be_cleared_by_inert_values() {
        for reverse in [
            "null",
            "{}",
            r#"{"bridges":[],"portals":[]}"#,
            r#"{"unknownReverseOption":null}"#,
            r#"{"unknownReverseOption":{}}"#,
            r#"{"unknownReverseOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "reverse":{"bridges":[{"tag":"bridge","domain":"example.com"}]},
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}]
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "reverse": {reverse}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedReverseFeature)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_reverse_settings() {
        for reverse in [
            r#"{"bridges":[{"tag":"bridge","domain":"example.com"}],"portals":[]}"#,
            r#"{"bridges":[],"portals":[{"tag":"portal","domain":"example.com"}]}"#,
            r#"{"bridges":[],"portals":[],"unknownReverseOption":true}"#,
            r#"{"bridges":[],"portals":[],"unknownReverseOption":{"key":"value"}}"#,
            r#"{"bridges":[],"portals":[],"unknownReverseOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "reverse": {reverse}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedReverseFeature)
            ));
        }
    }

    #[test]
    fn merged_active_geodata_cannot_be_cleared_by_inert_values() {
        for geodata in [
            "null",
            "{}",
            r#"{"loader":"standard"}"#,
            r#"{"geoip":"geoip.dat","geosite":"geosite.dat"}"#,
            r#"{"unknownGeodataOption":null}"#,
            r#"{"unknownGeodataOption":{}}"#,
            r#"{"unknownGeodataOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "geodata":{"loader":"memconservative"}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "geodata": {geodata}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedGeodataFeature)
            ));
        }
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
    fn accepts_inert_geodata_settings() {
        for geodata in [
            "{}",
            r#"{"loader":"standard"}"#,
            r#"{"geoip":"geoip.dat","geosite":"geosite.dat"}"#,
            r#"{"loader":"standard","geoip":"geoip.dat","geosite":"geosite.dat"}"#,
            r#"{"unknownGeodataOption":null}"#,
            r#"{"unknownGeodataOption":{}}"#,
            r#"{"unknownGeodataOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "geodata": {geodata}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_geodata_settings() {
        for geodata in [
            r#"{"loader":"memconservative"}"#,
            r#"{"geoip":"custom-geoip.dat"}"#,
            r#"{"geosite":"custom-geosite.dat"}"#,
            r#"{"unknownGeodataOption":true}"#,
            r#"{"unknownGeodataOption":{"key":"value"}}"#,
            r#"{"unknownGeodataOption":[true]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "geodata": {geodata}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedGeodataFeature)
            ));
        }
    }

    #[test]
    fn accepts_inert_top_level_dns_settings() {
        for dns in [
            "null",
            "{}",
            r#"{"servers":[],"hosts":{}}"#,
            r#"{"servers":null,"hosts":null}"#,
            r#"{"servers":[],"hosts":{},"clientIp":"","queryStrategy":"UseIP","disableCache":false,"serveStale":false,"serveExpiredTTL":0,"disableFallback":false,"disableFallbackIfMatch":false,"enableParallelQuery":false,"useSystemHosts":false,"tag":""}"#,
            r#"{"servers":[],"hosts":{},"queryStrategy":""}"#,
            r#"{"unknownDnsOption":{}}"#,
            r#"{"unknownDnsOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "dns": {dns}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_active_top_level_dns_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "dns": {
            "servers": ["1.1.1.1", "tcp://8.8.8.8", {"address":"9.9.9.9","port":53,"domains":["domain:example.com","geosite:private"],"expectIPs":["1.1.1.1","geoip:private"]}],
            "hosts": {"example.com":"127.0.0.1"},
            "queryStrategy":"UseIPv4",
            "disableFallback":true,
            "disableFallbackIfMatch":true
          }
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_top_level_dns_host_array_values() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "dns": {
            "servers": ["1.1.1.1"],
            "hosts": {"example.com":["127.0.0.1", "::1"], "alias.example":"example.com"}
          }
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_top_level_dns_client_ip_values() {
        for field in ["clientIp", "clientIP"] {
            for client_ip in ["1.2.3.4", "2001:db8::1"] {
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "dns": {{"{field}":"{client_ip}"}}
                    }}
                    "#,
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_dns_server_client_ip_values() {
        for field in ["clientIp", "clientIP"] {
            for client_ip in ["", "1.2.3.4", "2001:db8::1"] {
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "dns": {{"servers":[{{"address":"1.1.1.1","{field}":"{client_ip}"}}]}}
                    }}
                    "#,
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_dns_server_query_strategy_values() {
        for query_strategy in ["", "UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "dns": {{"servers":[{{"address":"1.1.1.1","queryStrategy":"{query_strategy}"}}]}}
                }}
                "#,
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_dns_server_skip_fallback_values() {
        for skip_fallback in ["true", "false", "null"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "dns": {{"servers":[{{"address":"1.1.1.1","skipFallback":{skip_fallback}}}]}}
                }}
                "#,
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_top_level_dns_settings() {
        for dns in [
            r#"{"servers":{},"hosts":[]}"#,
            r#"{"servers":[{}]}"#,
            r#"{"servers":[""]}"#,
            r#"{"servers":["   "]}"#,
            r#"{"servers":[{"address":""}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","port":0}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","port":65536}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","unknown":true}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","domains":"example.com"}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","domains":[""]}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","domains":["geosite:us"]}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","expectIPs":"1.1.1.1"}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","expectIPs":[""]}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","expectIPs":["geoip:us"]}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","clientIP":true}]}"#,
            r#"{"servers":[{"address":"1.1.1.1","clientIP":"not-an-ip"}]}"#,
            r#"{"servers":["tcp://1.1.1.1:0"]}"#,
            r#"{"servers":[{"address":"udp://1.1.1.1:0"}]}"#,
            r#"{"servers":["tcp://1.1.1.1:65536"]}"#,
            r#"{"servers":["tcp://1.1.1.1:notaport"]}"#,
            r#"{"servers":[{"address":"udp://1.1.1.1:"}]}"#,
            r#"{"servers":["https://dns.google/dns-query"]}"#,
            r#"{"servers":[{"address":"tls://1.1.1.1"}]}"#,
            r#"{"hosts":{"example.com":["127.0.0.1", true]}}"#,
            r#"{"clientIp":"not-an-ip"}"#,
            r#"{"disableCache":true}"#,
            r#"{"serveStale":true}"#,
            r#"{"serveExpiredTTL":3600}"#,
            r#"{"enableParallelQuery":true}"#,
            r#"{"useSystemHosts":true}"#,
            r#"{"tag":"dns"}"#,
            r#"{"unknownDnsOption":true}"#,
            r#"{"unknownDnsOption":{"key":"value"}}"#,
            r#"{"unknownDnsOption":[true]}"#,
            r#"[]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "dns": {dns}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTopLevelDnsFeature)
            ));
        }
    }

    #[test]
    fn merged_active_policy_cannot_be_cleared_by_inert_values() {
        for policy in [
            "null",
            "{}",
            r#"{"levels":{},"system":{}}"#,
            r#"{"unknownPolicyOption":null}"#,
            r#"{"unknownPolicyOption":{}}"#,
            r#"{"unknownPolicyOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "policy":{"levels":{"1":{"handshake":4}}},
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}]
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "policy": {policy}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedPolicyFeature)
            ));
        }
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
    fn accepts_inert_policy_settings() {
        for policy in [
            r#"{"levels": {}, "system": {}}"#,
            r#"{"levels": {"0":{"statsUserUplink":false}}, "system": {}}"#,
            r#"{"levels": {"0":{"statsUserDownlink":false}}, "system": {}}"#,
            r#"{"levels": {"0":{"statsUserUplink":false,"statsUserDownlink":false}}, "system": {}}"#,
            r#"{"levels":{"1":{"statsUserUplink":false}},"system":{}}"#,
            r#"{"levels":{"1":{"statsUserDownlink":false}},"system":{}}"#,
            r#"{"levels":{"1":{"statsUserUplink":false,"statsUserDownlink":false}},"system":{}}"#,
            r#"{"levels":{"0":{"connIdle":300}},"system":{}}"#,
            r#"{"levels":{"0":{"uplinkOnly":1}},"system":{}}"#,
            r#"{"levels":{"0":{"downlinkOnly":1}},"system":{}}"#,
            r#"{"levels":{"0":{"connIdle":300,"uplinkOnly":1,"downlinkOnly":1}},"system":{}}"#,
            r#"{"levels": null, "system": null}"#,
            r#"{"unknownPolicyOption": null}"#,
            r#"{"unknownPolicyOption": {}}"#,
            r#"{"unknownPolicyOption": []}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "policy": {policy}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_policy_level_zero_handshake_timeout() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "policy": {"levels":{"0":{"handshake":4}},"system":{}}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_policy_system_stats_flags() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "policy": {"levels":{},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_policy_settings() {
        for policy in [
            r#"{"levels":{"1":{"handshake":4}},"system":{}}"#,
            r#"{"levels":{"0":{"connIdle":299}},"system":{}}"#,
            r#"{"levels":{"0":{"connIdle":301}},"system":{}}"#,
            r#"{"levels":{"0":{"uplinkOnly":2}},"system":{}}"#,
            r#"{"levels":{"0":{"downlinkOnly":2}},"system":{}}"#,
            r#"{"levels":{"1":{"connIdle":300}},"system":{}}"#,
            r#"{"levels":{"1":{"uplinkOnly":1}},"system":{}}"#,
            r#"{"levels":{"1":{"downlinkOnly":1}},"system":{}}"#,
            r#"{"levels":{"0":{"statsUserUplink":true}},"system":{}}"#,
            r#"{"levels":{"0":{"statsUserDownlink":true}},"system":{}}"#,
            r#"{"levels":{"1":{"statsUserUplink":true}},"system":{}}"#,
            r#"{"levels":{"1":{"statsUserDownlink":true}},"system":{}}"#,
            r#"{"levels":{"abc":{"statsUserUplink":false}},"system":{}}"#,
            r#"{"levels":{"-1":{"statsUserUplink":false}},"system":{}}"#,
            r#"{"levels":{"4294967296":{"statsUserUplink":false}},"system":{}}"#,
            r#"{"levels":{"abc":{"statsUserDownlink":false}},"system":{}}"#,
            r#"{"levels":{},"system":{"statsInboundUplink":"true"}}"#,
            r#"{"levels":{},"system":{"statsUserUplink":true}}"#,
            r#"{"levels":{},"system":{},"unknownPolicyOption":true}"#,
            r#"{"levels":{},"system":{},"unknownPolicyOption":{"key":"value"}}"#,
            r#"{"levels":{},"system":{},"unknownPolicyOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "policy": {policy}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedPolicyFeature)
            ));
        }
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
    fn accepts_inert_unknown_stats_settings() {
        for stats in [
            r#"{"unknownStatsOption":null}"#,
            r#"{"unknownStatsOption":{}}"#,
            r#"{"unknownStatsOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "stats": {stats}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn merged_active_stats_cannot_be_cleared_by_inert_values() {
        for stats in [
            r#"{"unknownStatsOption":null}"#,
            r#"{"unknownStatsOption":{}}"#,
            r#"{"unknownStatsOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "stats":{"inboundUplink":true}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "stats": {stats}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedStatsFeature)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_stats_settings() {
        for stats in [r#"true"#, r#"{"inboundUplink":true}"#] {
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
    fn accepts_inert_observatory_settings() {
        for observatory in [
            r#"{"subjectSelector": [], "probeURL": ""}"#,
            r#"{"subjectSelector": null, "probeURL": ""}"#,
            r#"{"subjectSelector": [], "probeURL": "https://www.google.com/generate_204"}"#,
            r#"{"subjectSelector": null, "probeURL": "https://www.google.com/generate_204"}"#,
            r#"{"unknownObservatoryOption":null}"#,
            r#"{"unknownObservatoryOption":{}}"#,
            r#"{"unknownObservatoryOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "observatory": {observatory}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_observatory_settings() {
        for observatory in [
            r#"{"subjectSelector":["proxy"],"probeURL":"https://example.com/generate_204"}"#,
            r#"{"unknownObservatoryOption":true}"#,
            r#"{"unknownObservatoryOption":{"key":"value"}}"#,
            r#"{"unknownObservatoryOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "observatory": {observatory}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedObservatoryFeature)
            ));
        }
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
    fn accepts_inert_burst_observatory_settings() {
        for burst_observatory in [
            r#"{"subjectSelector": [], "pingConfig": null}"#,
            r#"{"subjectSelector": null, "pingConfig": null}"#,
            r#"{"subjectSelector": [], "pingConfig": {"destination":"https://www.google.com/generate_204"}}"#,
            r#"{"subjectSelector": null, "pingConfig": {"destination":"https://www.google.com/generate_204"}}"#,
            r#"{"unknownBurstObservatoryOption":null}"#,
            r#"{"unknownBurstObservatoryOption":{}}"#,
            r#"{"unknownBurstObservatoryOption":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "burstObservatory": {burst_observatory}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_burst_observatory_settings() {
        for burst_observatory in [
            r#"{"subjectSelector":["proxy"],"pingConfig":null}"#,
            r#"{"subjectSelector":[],"pingConfig":{"destination":"https://example.com/generate_204"}}"#,
            r#"{"subjectSelector":["proxy"],"pingConfig":{"destination":"https://example.com/generate_204"}}"#,
            r#"{"unknownBurstObservatoryOption":true}"#,
            r#"{"unknownBurstObservatoryOption":{"key":"value"}}"#,
            r#"{"unknownBurstObservatoryOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "burstObservatory": {burst_observatory}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedBurstObservatoryFeature)
            ));
        }
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
    fn accepts_inert_fakedns_settings() {
        for fakedns in [
            r#"{}"#,
            r#"[]"#,
            r#"[{"ipPool":"","poolSize":0}]"#,
            r#"[{"unknownFakeDnsOption":null}]"#,
            r#"[{"unknownFakeDnsOption":{}}]"#,
            r#"[{"unknownFakeDnsOption":[]}]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "fakedns": {fakedns}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
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
    fn merged_active_fakedns_cannot_be_cleared_by_inert_values() {
        for fakedns in [
            r#"{"ipPool":"","poolSize":0}"#,
            r#"[{"ipPool":"","poolSize":0}]"#,
            r#"[{"unknownFakeDnsOption":null}]"#,
            r#"[{"unknownFakeDnsOption":{}}]"#,
            r#"[{"unknownFakeDnsOption":[]}]"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "fakedns":{"ipPool":"198.18.0.0/15","poolSize":65535}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "fakedns": {fakedns}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedFakeDnsFeature)
            ));
        }
    }

    #[test]
    fn merged_active_metrics_cannot_be_cleared_by_inert_values() {
        for metrics in [
            "null",
            "{}",
            r#"{"tag":""}"#,
            r#"{"unknownMetricsOption":null}"#,
            r#"{"unknownMetricsOption":{}}"#,
            r#"{"unknownMetricsOption":[]}"#,
        ] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "metrics":{"tag":"metrics"},
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}]
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "metrics": {metrics}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedMetricsFeature)
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
    fn accepts_inert_metrics_settings() {
        for metrics in [
            r#"{"tag":"","unknownMetricsOption":null}"#,
            r#"{"tag":"","unknownMetricsOption":{}}"#,
            r#"{"tag":"","unknownMetricsOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "metrics": {metrics}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_metrics_settings() {
        for metrics in [
            r#"{"tag":"metrics"}"#,
            r#"{"tag":"","unknownMetricsOption":true}"#,
            r#"{"tag":"","unknownMetricsOption":{"key":"value"}}"#,
            r#"{"tag":"","unknownMetricsOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "metrics": {metrics}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedMetricsFeature)
            ));
        }
    }

    #[test]
    fn accepts_disabled_default_equivalent_inbound_sniffing_settings() {
        for (dest_override, domains_excluded) in [("[]", "[]"), ("null", "null")] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{{"enabled":false,"destOverride":{dest_override},"domainsExcluded":{domains_excluded},"metadataOnly":false,"routeOnly":false}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
            assert!(!sniffing.enabled);
            assert!(sniffing.dest_override.is_empty());
            assert!(sniffing.domains_excluded.is_empty());
            assert!(!sniffing.metadata_only);
            assert!(!sniffing.route_only);
        }
    }

    #[test]
    fn accepts_nullable_inbound_sniffing_boolean_defaults() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":null,"metadataOnly":null,"routeOnly":null}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(!sniffing.enabled);
        assert!(!sniffing.metadata_only);
        assert!(!sniffing.route_only);
    }

    #[test]
    fn accepts_disabled_inbound_sniffing_metadata_options() {
        for field in [
            r#""destOverride":["http"]"#,
            r#""domainsExcluded":["example.com"]"#,
            r#""metadataOnly":true"#,
            r#""routeOnly":true"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{{"enabled":false,{field}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_enabled_http_inbound_sniffing_destination_override() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["http"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["http"]);
    }

    #[test]
    fn accepts_enabled_tls_inbound_sniffing_destination_override() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["tls"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["tls"]);
    }

    #[test]
    fn accepts_enabled_http_and_tls_inbound_sniffing_destination_overrides() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["http","tls"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["http", "tls"]);
    }

    #[test]
    fn rejects_enabled_fakedns_inbound_sniffing_destination_override() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["fakedns"]}}],
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
    fn accepts_enabled_quic_inbound_sniffing_destination_override() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["quic"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["quic"]);
    }

    #[test]
    fn accepts_enabled_inbound_sniffing_route_only() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["http"],"routeOnly":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert!(sniffing.route_only);
        assert_eq!(sniffing.dest_override, ["http"]);
    }

    #[test]
    fn accepts_enabled_inbound_sniffing_metadata_only() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["http"],"metadataOnly":true}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert!(sniffing.metadata_only);
        assert_eq!(sniffing.dest_override, ["http"]);
    }

    #[test]
    fn accepts_enabled_inbound_sniffing_domains_excluded() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{"enabled":true,"destOverride":["http","tls"],"domainsExcluded":["blocked.example","geosite:private","Geosite:cn"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(
            sniffing.domains_excluded,
            ["blocked.example", "geosite:private", "Geosite:cn"]
        );
        assert_eq!(sniffing.dest_override, ["http", "tls"]);
    }

    #[test]
    fn accepts_enabled_tls_sniffing_for_http_connect_inbounds() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http","sniffing":{"enabled":true,"destOverride":["tls"]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["tls"]);
    }

    #[test]
    fn accepts_enabled_http_sniffing_for_http_inbounds() {
        for dest_override in [r#"["http"]"#, r#"["http","tls"]"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"http-in","port":1080,"protocol":"http","sniffing":{{"enabled":true,"destOverride":{dest_override}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
            assert!(sniffing.enabled);
        }
    }

    #[test]
    fn accepts_enabled_sniffing_for_dokodemo_door_inbounds() {
        for dest_override in [r#"["http"]"#, r#"["tls"]"#, r#"["http","tls"]"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"door","port":1080,"protocol":"dokodemo-door","settings":{{"address":"127.0.0.1","port":80}},"sniffing":{{"enabled":true,"destOverride":{dest_override}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
            assert!(sniffing.enabled);
        }
    }

    #[test]
    fn rejects_enabled_inbound_sniffing_fields() {
        for field in [
            r#""domainsExcluded":[""]"#,
            r#""destOverride":["http"],"domainsExcluded":["regexp:["]"#,
            r#""destOverride":["http"],"domainsExcluded":["domain: "]"#,
            r#""destOverride":["http"],"domainsExcluded":["keyword:"]"#,
            r#""destOverride":["http"],"domainsExcluded":[" blocked.example"]"#,
            r#""destOverride":["http"],"domainsExcluded":["Geosite:us"]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{{"enabled":true,{field}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedSniffingFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_unknown_inbound_sniffing_settings() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{{"enabled":false,"unknownSniffingOption":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
            assert!(sniffing.extra.contains_key("unknownSniffingOption"));
        }
    }

    #[test]
    fn rejects_unknown_inbound_sniffing_settings() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","sniffing":{{"enabled":false,"unknownSniffingOption":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedSniffingFeature)
            ));
        }
    }

    #[test]
    fn accepts_enabled_inbound_sniffing_without_effective_dest_override() {
        for (protocol, settings) in [
            ("socks", ""),
            (
                "dokodemo-door",
                r#", "settings":{"address":"127.0.0.1","port":80}"#,
            ),
        ] {
            for dest_override in [
                "",
                r#", "destOverride": null"#,
                r#", "destOverride": []"#,
                r#", "destOverride": [""]"#,
            ] {
                let json = format!(
                    r#"{{
                      "inbounds": [{{"tag":"in","port":1080,"protocol":"{protocol}"{settings},"sniffing":{{"enabled":true{dest_override}}}}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                    }}"#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                config.validate().unwrap();
                let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
                assert!(sniffing.enabled);
                assert!(!sniffing.has_effective_override());
            }
        }
    }

    #[test]
    fn accepts_disabled_default_equivalent_outbound_mux_settings() {
        for (concurrency, xudp_proxy_udp443) in
            [(-1, "reject"), (0, "reject"), (0, "skip"), (8, "reject")]
        {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","mux":{{"enabled":false,"concurrency":{concurrency},"xudpConcurrency":0,"xudpProxyUDP443":"{xudp_proxy_udp443}"}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let mux = config.outbounds[0].mux.as_ref().unwrap();
            assert_eq!(mux.concurrency, Some(concurrency));
            assert_eq!(mux.xudp_concurrency, Some(0));
            assert_eq!(mux.xudp_proxy_udp443, xudp_proxy_udp443);
        }

        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":null}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(!config.outbounds[0].mux.as_ref().unwrap().enabled);

        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","mux":{"enabled":false,"xudpProxyUDP443":null}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0].mux.as_ref().unwrap().xudp_proxy_udp443,
            ""
        );
    }

    #[test]
    fn rejects_outbound_mux_runtime_knobs() {
        for field in [
            r#""concurrency":16"#,
            r#""xudpConcurrency":16"#,
            r#""xudpProxyUDP443":"allow""#,
            r#""xudpProxyUDP443":"invalid""#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","mux":{{"enabled":false,{field}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedMuxFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_unknown_outbound_mux_settings() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","mux":{{"enabled":false,"unknownMuxOption":{unknown_value}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let mux = config.outbounds[0].mux.as_ref().unwrap();
            assert!(mux.extra.contains_key("unknownMuxOption"));
        }
    }

    #[test]
    fn rejects_unknown_outbound_mux_settings() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","mux":{{"enabled":false,"unknownMuxOption":{unknown_value}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedMuxFeature)
            ));
        }
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
    fn rejects_unowned_outbound_server_fields() {
        for (protocol, fields, field) in [
            ("freedom", r#""user":"alice""#, "user"),
            ("freedom", r#""password":"secret""#, "password"),
            ("socks", r#""method":"chacha20-ietf-poly1305""#, "method"),
            (
                "http",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef""#,
                "id",
            ),
            ("shadowsocks", r#""security":"none""#, "security"),
            ("vmess", r#""encryption":"none""#, "encryption"),
            ("trojan", r#""encryption":"none""#, "encryption"),
            ("shadowsocks", r#""encryption":"none""#, "encryption"),
            ("socks", r#""encryption":"none""#, "encryption"),
            ("http", r#""encryption":"none""#, "encryption"),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"test-out","protocol":"{protocol}","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,{fields}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundServerField(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn accepts_inert_outbound_send_through() {
        for send_through in ["null", "\"\""] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","sendThrough":{send_through}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_freedom_ip_send_through() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","sendThrough":"127.0.0.1"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.outbounds[0].send_through.as_deref(),
            Some("127.0.0.1")
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_freedom_domain_send_through() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","sendThrough":"example.com"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.outbounds[0].send_through.as_deref(),
            Some("example.com")
        );
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "sendThrough"
        ));
    }

    #[test]
    fn rejects_non_freedom_outbound_send_through() {
        for (protocol, send_through) in [("blackhole", "127.0.0.1"), ("blackhole", "example.com")] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"test-out","protocol":"{protocol}","sendThrough":"{send_through}"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(
                config.outbounds[0].send_through.as_deref(),
                Some(send_through)
            );
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "sendThrough"
            ));
        }
    }

    #[test]
    fn accepts_inert_outbound_proxy_settings() {
        for proxy_settings in [
            "null",
            "{}",
            r#"{"unknown":null}"#,
            r#"{"unknown":{}}"#,
            r#"{"unknown":[]}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","proxySettings":{proxy_settings}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_blank_outbound_proxy_settings_tag() {
        for tag in ["", "   "] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","proxySettings":{{"tag":"{tag}"}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.outbounds[0]
                    .proxy_settings
                    .as_ref()
                    .unwrap()
                    .tag
                    .as_deref(),
                Some(tag)
            );
        }
    }

    #[test]
    fn accepts_freedom_proxy_settings_tag_to_proxy_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [
            {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy"}},
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .proxy_settings
                .as_ref()
                .unwrap()
                .tag
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn accepts_freedom_send_through_with_proxy_settings_tag_to_proxy_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [
            {"tag":"direct","protocol":"freedom","sendThrough":"127.0.0.1","proxySettings":{"tag":"proxy"}},
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0].send_through.as_deref(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn accepts_freedom_proxy_settings_tag_with_tls_to_proxy_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [
            {
              "tag":"direct",
              "protocol":"freedom",
              "proxySettings":{"tag":"proxy"},
              "streamSettings":{
                "security":"tls",
                "tlsSettings":{"serverName":"localhost","allowInsecure":true}
              }
            },
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .security
                .as_deref(),
            Some("tls")
        );
    }

    #[test]
    fn accepts_freedom_sockopt_dialer_proxy_to_proxy_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [
            {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"proxy"}}},
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .dialer_proxy
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn accepts_freedom_sockopt_dialer_proxy_with_tls_to_proxy_outbound() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [
            {
              "tag":"direct",
              "protocol":"freedom",
              "streamSettings":{
                "security":"tls",
                "tlsSettings":{"serverName":"localhost","allowInsecure":true},
                "sockopt":{"dialerProxy":"proxy"}
              }
            },
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
          ]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .dialer_proxy
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn rejects_unknown_proxy_settings_tag() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy"}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownOutboundTag(tag)) if tag == "proxy"
        ));
    }

    #[test]
    fn rejects_unknown_sockopt_dialer_proxy_tag() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"proxy"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownOutboundTag(tag)) if tag == "proxy"
        ));
    }

    #[test]
    fn rejects_unsupported_outbound_proxy_settings() {
        for outbounds in [
            r#"[
              {"tag":"direct","protocol":"blackhole","proxySettings":{"tag":"proxy"}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy"}},
              {"tag":"proxy","protocol":"freedom"}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"proxy"}}},
              {"tag":"proxy","protocol":"freedom"}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy"}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]},"proxySettings":{"tag":"direct"}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":true}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":false}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":0}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":""}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":{"key":"value"}}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
            r#"[
              {"tag":"direct","protocol":"freedom","proxySettings":{"tag":"proxy","unknown":[true]}},
              {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}
            ]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": {outbounds}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field))
                    if field == "proxySettings"
            ));
        }
    }

    #[test]
    fn accepts_null_unknown_outbound_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","unknownOutboundOption":{unknown_value}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(
                config.outbounds[0]
                    .extra
                    .contains_key("unknownOutboundOption")
            );
        }
    }

    #[test]
    fn rejects_unknown_outbound_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","unknownOutboundOption":{unknown_value}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field))
                    if field == "unknownOutboundOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_outbound_settings_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"unknownOutboundSetting":{unknown_value}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let settings = config.outbounds[0].settings.as_ref().unwrap();
            assert!(settings.extra.contains_key("unknownOutboundSetting"));
        }
    }

    #[test]
    fn rejects_active_unknown_outbound_settings_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"unknownOutboundSetting":{unknown_value}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(field))
                    if field == "unknownOutboundSetting"
            ));
        }
    }

    #[test]
    fn accepts_inert_outbound_server_level_zero() {
        for (protocol, extra) in [
            ("socks", r#""user":"alice","password":"secret","#),
            ("http", r#""user":"alice","password":"secret","#),
            (
                "shadowsocks",
                r#""method":"chacha20-ietf-poly1305","password":"secret","#,
            ),
            (
                "vmess",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef","security":"none","#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,{extra}"level":0}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
            assert_eq!(server.level, Some(0));
        }
    }

    #[test]
    fn rejects_active_outbound_server_level() {
        for (protocol, extra) in [
            ("socks", r#""user":"alice","password":"secret","#),
            ("http", r#""user":"alice","password":"secret","#),
            (
                "shadowsocks",
                r#""method":"chacha20-ietf-poly1305","password":"secret","#,
            ),
            (
                "vmess",
                r#""id":"01234567-89ab-cdef-0123-456789abcdef","security":"none","#,
            ),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,{extra}"level":1}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "level"
            ));
        }
    }

    #[test]
    fn rejects_unowned_outbound_server_level() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"dns-out","protocol":"dns","settings":{"servers":[{"address":"127.0.0.1","port":5353,"level":1}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundServerField(field)) if field == "level"
        ));
    }

    #[test]
    fn accepts_inert_unknown_outbound_server_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"socks-out","protocol":"socks","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,"unknownServerOption":{unknown_value}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let server = &config.outbounds[0].settings.as_ref().unwrap().servers[0];
            assert!(server.extra.contains_key("unknownServerOption"));
        }
    }

    #[test]
    fn rejects_active_unknown_outbound_server_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"socks-out","protocol":"socks","settings":{{"servers":[{{"address":"127.0.0.1","port":1081,"unknownServerOption":{unknown_value}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundServerField(field))
                    if field == "unknownServerOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_blackhole_response_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"response":{{"type":"http","unknownResponseOption":{unknown_value}}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_blackhole_none_response() {
        for response in [r#"{"type":"none"}"#, "{}", r#"{"type":null}"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"response":{response}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_active_unknown_blackhole_response_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"response":{{"type":"http","unknownResponseOption":{unknown_value}}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedBlackholeResponseField(field))
                    if field == "unknownResponseOption"
            ));
        }
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
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"raw","security":"none","rawSettings":{{"header":{{}},"unknownRawOption":{unknown_value}}}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"network":"tcp","tcpSettings":{{"header":{{}},"unknownTcpOption":{unknown_value}}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
            assert!(
                config.inbounds[0]
                    .stream_settings
                    .as_ref()
                    .unwrap()
                    .raw_settings
                    .as_ref()
                    .unwrap()
                    .extra
                    .contains_key("unknownRawOption")
            );
            assert!(
                config.outbounds[0]
                    .stream_settings
                    .as_ref()
                    .unwrap()
                    .tcp_settings
                    .as_ref()
                    .unwrap()
                    .extra
                    .contains_key("unknownTcpOption")
            );
        }
    }

    #[test]
    fn accepts_raw_tcp_none_header_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"none"}}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"network":"raw","rawSettings":{"header":{"type":"none"}}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tcp_settings
                .as_ref()
                .unwrap()
                .header
                .as_ref()
                .unwrap(),
            &serde_json::json!({"type": "none"})
        );
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .raw_settings
                .as_ref()
                .unwrap()
                .header
                .as_ref()
                .unwrap(),
            &serde_json::json!({"type": "none"})
        );
    }

    #[test]
    fn rejects_unknown_raw_tcp_stream_settings() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"rawSettings":{{"unknownRawOption":{unknown_value}}}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedRawTransportFeature)
            ));
        }
    }

    #[test]
    fn accepts_null_unknown_stream_settings_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"unknownStreamOption":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(
                config.inbounds[0]
                    .stream_settings
                    .as_ref()
                    .unwrap()
                    .extra
                    .contains_key("unknownStreamOption")
            );
        }
    }

    #[test]
    fn rejects_unknown_stream_settings_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"unknownStreamOption":{unknown_value}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedStreamSettingsField(field)) if field == "unknownStreamOption"
            ));
        }
    }

    #[test]
    fn parses_inert_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpFastOpen":false,"tcpKeepAliveInterval":0,"tcpKeepAliveIdle":0,"tcpUserTimeout":0,"mark":0,"tproxy":"off","domainStrategy":"AsIs","dialerProxy":"","tcpMptcp":false,"interface":"","tcpNoDelay":false}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let sockopt = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .sockopt
            .as_ref()
            .unwrap();
        assert!(!sockopt.tcp_fast_open);
        assert_eq!(sockopt.tcp_keep_alive_interval, Some(0));
        assert_eq!(sockopt.tcp_keep_alive_idle, Some(0));
        assert_eq!(sockopt.tcp_user_timeout, Some(0));
        assert_eq!(sockopt.mark, Some(0));
        assert_eq!(sockopt.tproxy.as_deref(), Some("off"));
        assert_eq!(sockopt.domain_strategy.as_deref(), Some("AsIs"));
        assert_eq!(sockopt.dialer_proxy.as_deref(), Some(""));
        assert!(!sockopt.tcp_mptcp);
        assert_eq!(sockopt.interface_name.as_deref(), Some(""));
        assert!(!sockopt.tcp_no_delay);
    }

    #[test]
    fn accepts_nullable_sockopt_boolean_defaults() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpFastOpen":null,"tcpMptcp":null,"tcpNoDelay":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tcpFastOpen":null,"tcpMptcp":null,"tcpNoDelay":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let inbound_sockopt = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .sockopt
            .as_ref()
            .unwrap();
        assert!(!inbound_sockopt.tcp_fast_open);
        assert!(!inbound_sockopt.tcp_mptcp);
        assert!(!inbound_sockopt.tcp_no_delay);
        let outbound_sockopt = config.outbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .sockopt
            .as_ref()
            .unwrap();
        assert!(!outbound_sockopt.tcp_fast_open);
        assert!(!outbound_sockopt.tcp_mptcp);
        assert!(!outbound_sockopt.tcp_no_delay);
    }

    #[test]
    fn accepts_outbound_tcp_fast_open_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tcpFastOpen":true}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .tcp_fast_open
        );
    }

    #[test]
    fn rejects_inbound_tcp_fast_open_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpFastOpen":true}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedSockoptFeature)
        ));
    }

    #[test]
    fn accepts_tcp_no_delay_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpNoDelay":true}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tcpNoDelay":true}}}]
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
                .as_ref()
                .unwrap()
                .tcp_no_delay
        );
        assert!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .tcp_no_delay
        );
    }

    #[test]
    fn accepts_tcp_keepalive_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpKeepAliveInterval":15,"tcpKeepAliveIdle":30}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tcpKeepAliveInterval":15,"tcpKeepAliveIdle":30}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let inbound_sockopt = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .sockopt
            .as_ref()
            .unwrap();
        let outbound_sockopt = config.outbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .sockopt
            .as_ref()
            .unwrap();
        assert_eq!(inbound_sockopt.tcp_keep_alive_interval, Some(15));
        assert_eq!(inbound_sockopt.tcp_keep_alive_idle, Some(30));
        assert_eq!(outbound_sockopt.tcp_keep_alive_interval, Some(15));
        assert_eq!(outbound_sockopt.tcp_keep_alive_idle, Some(30));
    }

    #[test]
    fn accepts_tcp_user_timeout_sockopt_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"sockopt":{"tcpUserTimeout":1000}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"tcpUserTimeout":1000}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .tcp_user_timeout,
            Some(1000)
        );
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .tcp_user_timeout,
            Some(1000)
        );
    }

    #[test]
    fn accepts_use_ip_sockopt_domain_strategy_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":"UseIP"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .domain_strategy
                .as_deref(),
            Some("UseIP")
        );
    }

    #[test]
    fn accepts_ip_family_sockopt_domain_strategy_stream_settings() {
        for strategy in ["UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"sockopt":{{"domainStrategy":"{strategy}"}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.outbounds[0]
                    .stream_settings
                    .as_ref()
                    .unwrap()
                    .sockopt
                    .as_ref()
                    .unwrap()
                    .domain_strategy
                    .as_deref(),
                Some(strategy)
            );
        }
    }

    #[test]
    fn accepts_raw_tcp_accept_proxy_protocol_stream_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"tcpSettings":{"acceptProxyProtocol":true}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tcp_settings
                .as_ref()
                .unwrap()
                .accept_proxy_protocol
        );
    }

    #[test]
    fn accepts_nullable_raw_tcp_accept_proxy_protocol_defaults() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"tcpSettings":{"acceptProxyProtocol":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"rawSettings":{"acceptProxyProtocol":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            !config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tcp_settings
                .as_ref()
                .unwrap()
                .accept_proxy_protocol
        );
        assert!(
            !config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .raw_settings
                .as_ref()
                .unwrap()
                .accept_proxy_protocol
        );
    }

    #[test]
    fn accepts_tls_inbound_accept_proxy_protocol_stream_settings() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-proxy-protocol-cert.pem");
        let key = dir.join("xrs-config-proxy-protocol-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"certificates":[{{"certificateFile":"{}","keyFile":"{}"}}]}},"tcpSettings":{{"acceptProxyProtocol":true}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        config.validate().unwrap();
        assert!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tcp_settings
                .as_ref()
                .unwrap()
                .accept_proxy_protocol
        );
    }

    #[test]
    fn accepts_empty_unknown_sockopt_stream_settings() {
        for sockopt in [
            r#"{"unknownSockoptOption":null}"#,
            r#"{"unknownSockoptOption":{}}"#,
            r#"{"unknownSockoptOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"sockopt":{sockopt}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let sockopt = config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap();
            assert!(sockopt.extra.contains_key("unknownSockoptOption"));
        }
    }

    #[test]
    fn parses_inert_tls_stream_settings() {
        for tls_settings in [
            "{}",
            r#"{"unknownTlsOption":null}"#,
            r#"{"unknownTlsOption":{}}"#,
            r#"{"unknownTlsOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"tlsSettings":{tls_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"tlsSettings":{tls_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_null_tls_vector_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"tlsSettings":{"alpn":null,"certificates":null,"pinnedPeerCertificateChainSha256":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"tlsSettings":{"alpn":null,"certificates":null,"pinnedPeerCertificateChainSha256":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let tls_settings = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .tls_settings
            .as_ref()
            .unwrap();
        assert!(tls_settings.alpn.is_empty());
        assert!(tls_settings.certificates.is_empty());
        assert!(tls_settings.pinned_peer_certificate_chain_sha256.is_empty());
    }

    #[test]
    fn accepts_nullable_tls_boolean_defaults() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"tlsSettings":{"allowInsecure":null,"disableSystemRoot":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":null,"disableSystemRoot":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let inbound_tls = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .tls_settings
            .as_ref()
            .unwrap();
        assert!(!inbound_tls.allow_insecure);
        assert!(!inbound_tls.disable_system_root);
        let outbound_tls = config.outbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .tls_settings
            .as_ref()
            .unwrap();
        assert!(!outbound_tls.allow_insecure);
        assert!(!outbound_tls.disable_system_root);
    }

    #[test]
    fn accepts_inactive_inbound_tls_stream_settings_without_tls_security() {
        for stream_settings in [
            r#"{"tlsSettings":{"allowInsecure":true}}"#,
            r#"{"security":"none","tlsSettings":{"serverName":"example.com","alpn":["h2"]}}"#,
            r#"{"tlsSettings":{"certificates":[{"certificate":"cert","key":"key"}]}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
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
    fn accepts_empty_outbound_tls_certificate_entries() {
        for certificates in [
            r#"[{}]"#,
            r#"[{"certificateFile":"","keyFile":""}]"#,
            r#"[{}, {"certificateFile":"","keyFile":""}]"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"example.com","certificates":{certificates}}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
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

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn accepts_inbound_tls_alpn_stream_settings() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-alpn-cert.pem");
        let key = dir.join("xrs-config-inbound-alpn-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"alpn":["h2","http/1.1"],"certificates":[{{"certificateFile":"{}","keyFile":"{}"}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_inbound_tls_server_name_stream_settings() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-server-name-cert.pem");
        let key = dir.join("xrs-config-inbound-server-name-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"example.com","certificates":[{{"certificateFile":"{}","keyFile":"{}"}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .tls_settings
                .as_ref()
                .unwrap()
                .server_name
                .as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn accepts_null_inbound_tls_certificate_extra() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-null-extra-cert.pem");
        let key = dir.join("xrs-config-inbound-null-extra-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"certificates":[{{"certificateFile":"{}","keyFile":"{}","ocspStapling":null}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_inbound_tls_certificate_extra() {
        let dir = std::env::temp_dir();
        let cert = dir.join("xrs-config-inbound-extra-cert.pem");
        let key = dir.join("xrs-config-inbound-extra-key.pem");
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let json = format!(
            r#"{{
              "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{{"certificates":[{{"certificateFile":"{}","keyFile":"{}","ocspStapling":true}}]}}}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
            }}"#,
            cert.display(),
            key.display()
        );

        let config: RootConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundTlsSettingsField(field)) if field == "ocspStapling"
        ));
    }

    #[test]
    fn rejects_inbound_tls_client_style_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}],
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
    fn rejects_blank_outbound_tls_server_name() {
        for server_name in ["   ", " example.com", "example.com ", "\\texample.com"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"{server_name}"}}}}}}]
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
    fn accepts_empty_outbound_tls_alpn_entries() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","alpn":[""]}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_blank_outbound_tls_alpn() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","alpn":["   "]}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTlsTransportFeature)
        ));
    }

    #[test]
    fn rejects_unsupported_outbound_tls_stream_settings() {
        for (protocol, settings) in [
            (
                "dns",
                r#","settings":{"servers":[{"address":"example.com","port":443}]}"#,
            ),
            ("blackhole", ""),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"proxy","protocol":"{protocol}"{settings},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"example.com"}}}}}}]
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
    fn accepts_inactive_outbound_tls_stream_settings_without_tls_security() {
        for stream_settings in [
            r#"{"tlsSettings":{"alpn":["h2"]}}"#,
            r#"{"security":"none","tlsSettings":{"alpn":["h2"]}}"#,
            r#"{"tlsSettings":{"disableSystemRoot":true,"fingerprint":"chrome"}}"#,
            r#"{"security":"none","tlsSettings":{"disableSystemRoot":true,"fingerprint":"chrome"}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_tls_stream_settings() {
        for tls_settings in [
            r#"{"certificates":[{"certificateFile":"cert.pem"}]}"#,
            r#"{"disableSystemRoot":true}"#,
            r#"{"fingerprint":"chrome"}"#,
            r#"{"pinnedPeerCertificateChainSha256":["abc"]}"#,
            r#"{"minVersion":"1.3"}"#,
            r#"{"unknownTlsOption":true}"#,
            r#"{"unknownTlsOption":false}"#,
            r#"{"unknownTlsOption":0}"#,
            r#"{"unknownTlsOption":""}"#,
            r#"{"unknownTlsOption":{"key":"value"}}"#,
            r#"{"unknownTlsOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"security":"tls","tlsSettings":{tls_settings}}}}}],
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
        for reality_settings in [
            "{}",
            r#"{"show":null}"#,
            r#"{"serverNames":null,"shortIds":null}"#,
            r#"{"unknownRealityOption":null}"#,
            r#"{"unknownRealityOption":{}}"#,
            r#"{"unknownRealityOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"realitySettings":{reality_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"realitySettings":{reality_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_inactive_reality_settings_without_reality_security() {
        for stream_settings in [
            r#"{"security":"none","realitySettings":{"show":true,"dest":"example.com:443"}}"#,
            r#"{"security":"tls","tlsSettings":{},"realitySettings":{"serverNames":["example.com"],"privateKey":"private"}}"#,
            r#"{"realitySettings":{"unknownRealityOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
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
            r#"{"unknownRealityOption":false}"#,
            r#"{"unknownRealityOption":0}"#,
            r#"{"unknownRealityOption":""}"#,
            r#"{"unknownRealityOption":{"key":"value"}}"#,
            r#"{"unknownRealityOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"security":"reality","realitySettings":{reality_settings}}}}}]
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
        for (authority, expected_authority, unknown_value) in [
            (r#""""#, Some(""), "null"),
            ("null", None, "{}"),
            (r#""""#, Some(""), "[]"),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"grpcSettings":{{"serviceName":"","authority":{authority},"multiMode":false,"idle_timeout":0,"health_check_timeout":0,"permit_without_stream":false,"initial_windows_size":0,"noGRPCHeader":false,"unknownGrpcOption":{unknown_value}}}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"grpcSettings":{{}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let grpc = config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .grpc_settings
                .as_ref()
                .unwrap();
            assert_eq!(grpc.service_name.as_deref(), Some(""));
            assert_eq!(grpc.authority.as_deref(), expected_authority);
            assert!(!grpc.multi_mode);
            assert_eq!(grpc.idle_timeout, Some(0));
            assert_eq!(grpc.health_check_timeout, Some(0));
            assert!(!grpc.permit_without_stream);
            assert_eq!(grpc.initial_windows_size, Some(0));
            assert!(grpc.extra.contains_key("unknownGrpcOption"));
        }
    }

    #[test]
    fn grpc_stream_defaults_are_not_unsupported_features() {
        let settings: GrpcSettingsConfig = serde_json::from_str(r#"{"user_agent":""}"#).unwrap();
        assert!(!settings.has_unsupported_feature());

        let settings: GrpcSettingsConfig = serde_json::from_str(r#"{"user_agent":"xrs"}"#).unwrap();
        assert!(settings.has_unsupported_feature());
    }

    #[test]
    fn accepts_nullable_grpc_stream_boolean_defaults() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"grpcSettings":{"multiMode":null,"permit_without_stream":null,"noGRPCHeader":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"grpcSettings":{"multiMode":null,"permit_without_stream":null,"noGRPCHeader":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let grpc = config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .grpc_settings
            .as_ref()
            .unwrap();
        assert!(!grpc.multi_mode);
        assert!(!grpc.permit_without_stream);
        assert!(!grpc.no_grpc_header);
    }

    #[test]
    fn accepts_inactive_grpc_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","grpcSettings":{"serviceName":"svc","authority":"example.com","multiMode":true}}"#,
            r#"{"network":"raw","grpcSettings":{"idle_timeout":60,"health_check_timeout":20,"permit_without_stream":true}}"#,
            r#"{"grpcSettings":{"initial_windows_size":65535,"noGRPCHeader":true,"unknownGrpcOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_grpc_stream_settings() {
        for grpc_settings in [
            r#"{"serviceName":"svc"}"#,
            r#"{"authority":"example.com"}"#,
            r#"{"multiMode":true}"#,
            r#"{"idle_timeout":60}"#,
            r#"{"health_check_timeout":20}"#,
            r#"{"permit_without_stream":true}"#,
            r#"{"initial_windows_size":65535}"#,
            r#"{"noGRPCHeader":true}"#,
            r#"{"unknownGrpcOption":true}"#,
            r#"{"unknownGrpcOption":false}"#,
            r#"{"unknownGrpcOption":0}"#,
            r#"{"unknownGrpcOption":""}"#,
            r#"{"unknownGrpcOption":{"key":"value"}}"#,
            r#"{"unknownGrpcOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"grpc","grpcSettings":{grpc_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "grpc"
            ));
        }
    }

    #[test]
    fn parses_inert_xhttp_stream_settings() {
        for xhttp_settings in [
            r#"{}"#,
            r#"{"path":"","host":"","mode":""}"#,
            r#"{"mode":null}"#,
            r#"{"mode":"auto"}"#,
            r#"{"headers":null,"extra":null}"#,
            r#"{"headers":{},"extra":{}}"#,
            r#"{"headers":{"Host":[]}}"#,
            r#"{"xPaddingKey":"x_padding","xPaddingHeader":"X-Padding","xPaddingPlacement":"queryInHeader","xPaddingMethod":"repeat-x"}"#,
            r#"{"xPaddingKey":null,"xPaddingHeader":null,"xPaddingPlacement":null,"xPaddingMethod":null}"#,
            r#"{"uplinkHTTPMethod":"POST","sessionPlacement":"path","seqPlacement":"path","uplinkDataPlacement":"auto","noSSEHeader":false}"#,
            r#"{"noSSEHeader":false}"#,
            r#"{"noSSEHeader":null}"#,
            r#"{"unknownXhttpOption":null}"#,
            r#"{"unknownXhttpOption":{}}"#,
            r#"{"unknownXhttpOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"xhttpSettings":{xhttp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"xhttpSettings":{xhttp_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn xhttp_stream_defaults_are_not_unsupported_features() {
        for xhttp_settings in [
            r#"{"xPaddingKey":"x_padding"}"#,
            r#"{"xPaddingHeader":"X-Padding"}"#,
            r#"{"xPaddingPlacement":"queryInHeader"}"#,
            r#"{"xPaddingMethod":"repeat-x"}"#,
            r#"{"xPaddingKey":null,"xPaddingHeader":null,"xPaddingPlacement":null,"xPaddingMethod":null}"#,
            r#"{"uplinkHTTPMethod":"POST"}"#,
            r#"{"uplinkHTTPMethod":""}"#,
            r#"{"sessionPlacement":"path","seqPlacement":"path"}"#,
            r#"{"sessionPlacement":"","seqPlacement":""}"#,
            r#"{"uplinkDataPlacement":"auto"}"#,
            r#"{"uplinkDataPlacement":""}"#,
            r#"{"noSSEHeader":false}"#,
            r#"{"noSSEHeader":null}"#,
        ] {
            let settings: XhttpSettingsConfig = serde_json::from_str(xhttp_settings).unwrap();
            assert!(!settings.has_unsupported_feature());
        }

        for xhttp_settings in [
            r#"{"xPaddingKey":"custom_padding"}"#,
            r#"{"xPaddingHeader":"X-Custom-Padding"}"#,
            r#"{"xPaddingPlacement":"query"}"#,
            r#"{"xPaddingMethod":"random"}"#,
            r#"{"uplinkHTTPMethod":"GET"}"#,
            r#"{"sessionPlacement":"cookie"}"#,
            r#"{"seqPlacement":"query"}"#,
            r#"{"uplinkDataPlacement":"body"}"#,
            r#"{"noSSEHeader":true}"#,
        ] {
            let settings: XhttpSettingsConfig = serde_json::from_str(xhttp_settings).unwrap();
            assert!(settings.has_unsupported_feature());
        }
    }

    #[test]
    fn parses_inert_split_http_stream_settings() {
        for split_http_settings in [
            r#"{}"#,
            r#"{"path":"","host":"","mode":""}"#,
            r#"{"mode":null}"#,
            r#"{"mode":"auto"}"#,
            r#"{"headers":null,"xmux":null,"extra":null}"#,
            r#"{"headers":{},"xmux":{},"extra":{}}"#,
            r#"{"scMaxBufferedPosts":30}"#,
            r#"{"headers":{"Host":[]}}"#,
            r#"{"unknownSplitHttpOption":null}"#,
            r#"{"unknownSplitHttpOption":{}}"#,
            r#"{"unknownSplitHttpOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"splithttpSettings":{split_http_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"splithttpSettings":{split_http_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_inactive_split_http_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","splithttpSettings":{"path":"/split","host":"example.com","mode":"packet-up"}}"#,
            r#"{"network":"raw","splithttpSettings":{"headers":{"Host":"example.com"},"xmux":{"maxConcurrency":4},"extra":{"key":"value"}}}"#,
            r#"{"splithttpSettings":{"scMaxConcurrentPosts":100,"unknownSplitHttpOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn split_http_stream_defaults_are_not_unsupported_features() {
        for split_http_settings in [
            r#"{"scMaxBufferedPosts":null}"#,
            r#"{"scMaxBufferedPosts":30}"#,
            r#"{"scMinPostsIntervalMs":null}"#,
            r#"{"scMinPostsIntervalMs":30}"#,
            r#"{"scMinPostsIntervalMs":"30"}"#,
            r#"{"scMaxEachPostBytes":null}"#,
            r#"{"scMaxEachPostBytes":1000000}"#,
            r#"{"scMaxEachPostBytes":"1000000"}"#,
            r#"{"xPaddingKey":"x_padding"}"#,
            r#"{"xPaddingHeader":"X-Padding"}"#,
            r#"{"xPaddingPlacement":"queryInHeader"}"#,
            r#"{"xPaddingMethod":"repeat-x"}"#,
            r#"{"xPaddingKey":null,"xPaddingHeader":null,"xPaddingPlacement":null,"xPaddingMethod":null}"#,
            r#"{"xmux":{"maxConcurrency":{"from":0,"to":0},"maxConnections":{"from":0,"to":0},"cMaxReuseTimes":{"from":0,"to":0},"hMaxRequestTimes":{"from":0,"to":0},"hMaxReusableSecs":{"from":0,"to":0},"hKeepAlivePeriod":0}}"#,
            r#"{"uplinkHTTPMethod":"POST"}"#,
            r#"{"sessionPlacement":"path","seqPlacement":"path"}"#,
            r#"{"uplinkDataPlacement":"auto"}"#,
            r#"{"noGRPCHeader":false}"#,
            r#"{"noGRPCHeader":null}"#,
        ] {
            let settings: SplitHttpSettingsConfig =
                serde_json::from_str(split_http_settings).unwrap();
            assert!(!settings.has_unsupported_feature());
        }

        for split_http_settings in [
            r#"{"scMaxBufferedPosts":31}"#,
            r#"{"scMaxEachPostBytes":999999}"#,
            r#"{"scMaxEachPostBytes":"999999"}"#,
            r#"{"scMinPostsIntervalMs":10}"#,
            r#"{"scMinPostsIntervalMs":"10"}"#,
            r#"{"xPaddingKey":"custom_padding"}"#,
            r#"{"xPaddingHeader":"X-Custom-Padding"}"#,
            r#"{"xPaddingPlacement":"query"}"#,
            r#"{"xPaddingMethod":"random"}"#,
            r#"{"xmux":{"maxConcurrency":{}}}"#,
            r#"{"xmux":{"maxConcurrency":{"from":0}}}"#,
            r#"{"xmux":{"maxConcurrency":{"to":0}}}"#,
            r#"{"uplinkHTTPMethod":"GET"}"#,
            r#"{"sessionPlacement":"cookie"}"#,
            r#"{"seqPlacement":"query"}"#,
            r#"{"uplinkDataPlacement":"body"}"#,
            r#"{"noGRPCHeader":true}"#,
        ] {
            let settings: SplitHttpSettingsConfig =
                serde_json::from_str(split_http_settings).unwrap();
            assert!(settings.has_unsupported_feature());
        }
    }

    #[test]
    fn rejects_active_split_http_transport_even_with_default_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"network":"splithttp","splithttpSettings":{"scMaxBufferedPosts":30}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "splithttp"
        ));
    }

    #[test]
    fn rejects_unsupported_split_http_stream_settings() {
        for split_http_settings in [
            r#"{"path":"/split"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"mode":"packet-up"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"scMaxConcurrentPosts":100}"#,
            r#"{"scMaxEachPostBytes":"1m"}"#,
            r#"{"scMinPostsIntervalMs":10}"#,
            r#"{"xPaddingBytes":"100-1000"}"#,
            r#"{"xmux":{"maxConcurrency":1}}"#,
            r#"{"xmux":{"maxConcurrency":4}}"#,
            r#"{"xmux":{"maxConcurrency":{"from":1,"to":1}}}"#,
            r#"{"xmux":{"maxConcurrency":{"from":0,"to":1}}}"#,
            r#"{"xmux":{"maxConcurrency":{}}}"#,
            r#"{"xmux":{"maxConcurrency":{"from":0}}}"#,
            r#"{"xmux":{"maxConcurrency":{"to":0}}}"#,
            r#"{"xmux":{"hKeepAlivePeriod":1}}"#,
            r#"{"xmux":{"unknownXmuxOption":null}}"#,
            r#"{"xmux":{"unknownXmuxOption":{}}}"#,
            r#"{"xmux":{"unknownXmuxOption":[]}}"#,
            r#"{"extra":{"key":"value"}}"#,
            r#"{"scMaxConcurrentPosts":{}}"#,
            r#"{"unknownSplitHttpOption":true}"#,
            r#"{"unknownSplitHttpOption":false}"#,
            r#"{"unknownSplitHttpOption":0}"#,
            r#"{"unknownSplitHttpOption":""}"#,
            r#"{"unknownSplitHttpOption":{"key":"value"}}"#,
            r#"{"unknownSplitHttpOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"splithttp","splithttpSettings":{split_http_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "splithttp"
            ));
        }
    }

    #[test]
    fn parses_inert_http_upgrade_stream_settings() {
        for http_upgrade_settings in [
            r#"{}"#,
            r#"{"host":"","path":"","acceptProxyProtocol":false}"#,
            r#"{"acceptProxyProtocol":null}"#,
            r#"{"headers":null}"#,
            r#"{"headers":{}}"#,
            r#"{"headers":{"Host":[]}}"#,
            r#"{"unknownHttpUpgradeOption":null}"#,
            r#"{"unknownHttpUpgradeOption":{}}"#,
            r#"{"unknownHttpUpgradeOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"httpupgradeSettings":{http_upgrade_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"httpupgradeSettings":{http_upgrade_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_inactive_http_upgrade_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","httpupgradeSettings":{"host":"example.com","path":"/upgrade"}}"#,
            r#"{"network":"raw","httpupgradeSettings":{"headers":{"Host":"example.com"},"acceptProxyProtocol":true}}"#,
            r#"{"httpupgradeSettings":{"unknownHttpUpgradeOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_http_upgrade_stream_settings() {
        for http_upgrade_settings in [
            r#"{"host":"example.com"}"#,
            r#"{"path":"/upgrade"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"acceptProxyProtocol":true}"#,
            r#"{"unknownHttpUpgradeOption":true}"#,
            r#"{"unknownHttpUpgradeOption":false}"#,
            r#"{"unknownHttpUpgradeOption":0}"#,
            r#"{"unknownHttpUpgradeOption":""}"#,
            r#"{"unknownHttpUpgradeOption":{"key":"value"}}"#,
            r#"{"unknownHttpUpgradeOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"httpupgrade","httpupgradeSettings":{http_upgrade_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "httpupgrade"
            ));
        }
    }

    #[test]
    fn parses_inert_http_transport_stream_settings() {
        for (host, headers, expected_headers, unknown_value) in [
            ("[]", "null", None, "null"),
            ("null", "null", None, "null"),
            ("[]", "{}", Some(serde_json::json!({})), "{}"),
            ("[]", "{}", Some(serde_json::json!({})), "[]"),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"httpSettings":{{"host":{host},"path":"","method":"","headers":{headers},"read_idle_timeout":0,"health_check_timeout":0,"with_trailers":false,"unknownHttpOption":{unknown_value}}}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"httpSettings":{{}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let http = config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_settings
                .as_ref()
                .unwrap();
            assert!(http.host.is_empty());
            assert_eq!(http.path.as_deref(), Some(""));
            assert_eq!(http.method.as_deref(), Some(""));
            assert_eq!(http.headers.as_ref(), expected_headers.as_ref());
            assert_eq!(http.read_idle_timeout, Some(0));
            assert_eq!(http.health_check_timeout, Some(0));
            assert!(!http.with_trailers);
            assert!(http.extra.contains_key("unknownHttpOption"));
        }
    }

    #[test]
    fn accepts_nullable_http_transport_trailers_default() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"httpSettings":{"with_trailers":null}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"httpSettings":{"with_trailers":null}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(
            !config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_settings
                .as_ref()
                .unwrap()
                .with_trailers
        );
        assert!(
            !config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_settings
                .as_ref()
                .unwrap()
                .with_trailers
        );
    }

    #[test]
    fn accepts_inert_http_transport_empty_host_header() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"httpSettings":{"headers":{"Host":[]}}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"httpSettings":{"headers":{"Host":[]}}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .http_settings
                .as_ref()
                .unwrap()
                .headers
                .as_ref()
                .unwrap(),
            &serde_json::json!({"Host": []})
        );
    }

    #[test]
    fn accepts_inactive_http_transport_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","httpSettings":{"host":["example.com"],"path":"/h2","method":"PUT"}}"#,
            r#"{"network":"raw","httpSettings":{"headers":{"Host":"example.com"},"read_idle_timeout":60,"health_check_timeout":20,"with_trailers":true}}"#,
            r#"{"httpSettings":{"unknownHttpOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
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
            r#"{"unknownHttpOption":false}"#,
            r#"{"unknownHttpOption":0}"#,
            r#"{"unknownHttpOption":""}"#,
            r#"{"unknownHttpOption":{"key":"value"}}"#,
            r#"{"unknownHttpOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"http","httpSettings":{http_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "http"
            ));
        }
    }

    #[test]
    fn accepts_inactive_xhttp_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","xhttpSettings":{"path":"/xhttp","host":"example.com","mode":"packet-up"}}"#,
            r#"{"network":"raw","xhttpSettings":{"headers":{"Host":"example.com"},"extra":{"key":"value"}}}"#,
            r#"{"xhttpSettings":{"unknownXhttpOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_xhttp_stream_settings() {
        for xhttp_settings in [
            r#"{"path":"/xhttp"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"mode":"packet-up"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"xPaddingKey":"custom_padding"}"#,
            r#"{"xPaddingHeader":"X-Custom-Padding"}"#,
            r#"{"xPaddingPlacement":"query"}"#,
            r#"{"xPaddingMethod":"random"}"#,
            r#"{"uplinkHTTPMethod":"GET"}"#,
            r#"{"sessionPlacement":"cookie"}"#,
            r#"{"seqPlacement":"query"}"#,
            r#"{"uplinkDataPlacement":"body"}"#,
            r#"{"noSSEHeader":true}"#,
            r#"{"extra":{"key":"value"}}"#,
            r#"{"unknownXhttpOption":true}"#,
            r#"{"unknownXhttpOption":false}"#,
            r#"{"unknownXhttpOption":0}"#,
            r#"{"unknownXhttpOption":""}"#,
            r#"{"unknownXhttpOption":{"key":"value"}}"#,
            r#"{"unknownXhttpOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"xhttp","xhttpSettings":{xhttp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "xhttp"
            ));
        }
    }

    #[test]
    fn parses_inert_kcp_stream_settings() {
        for kcp_settings in [
            r#"{}"#,
            r#"{"mtu":0,"tti":0,"uplinkCapacity":0,"downlinkCapacity":0}"#,
            r#"{"mtu":1350,"tti":50,"uplinkCapacity":5,"downlinkCapacity":20}"#,
            r#"{"cwndMultiplier":1,"maxSendingWindow":2097152}"#,
            r#"{"readBufferSize":0,"writeBufferSize":0,"congestion":false}"#,
            r#"{"congestion":null}"#,
            r#"{"header":null,"seed":""}"#,
            r#"{"header":{}}"#,
            r#"{"header":{"type":"none"}}"#,
            r#"{"unknownKcpOption":null}"#,
            r#"{"unknownKcpOption":{}}"#,
            r#"{"unknownKcpOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"kcpSettings":{kcp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"kcpSettings":{kcp_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn kcp_stream_defaults_are_not_unsupported_features() {
        for kcp_settings in [
            r#"{"mtu":1350}"#,
            r#"{"tti":50}"#,
            r#"{"uplinkCapacity":5}"#,
            r#"{"downlinkCapacity":20}"#,
            r#"{"cwndMultiplier":1}"#,
            r#"{"maxSendingWindow":2097152}"#,
        ] {
            let settings: KcpSettingsConfig = serde_json::from_str(kcp_settings).unwrap();
            assert!(!settings.has_unsupported_feature());
        }

        for kcp_settings in [
            r#"{"mtu":1349}"#,
            r#"{"mtu":1351}"#,
            r#"{"tti":49}"#,
            r#"{"tti":51}"#,
            r#"{"uplinkCapacity":6}"#,
            r#"{"downlinkCapacity":21}"#,
            r#"{"cwndMultiplier":2}"#,
            r#"{"maxSendingWindow":2097151}"#,
        ] {
            let settings: KcpSettingsConfig = serde_json::from_str(kcp_settings).unwrap();
            assert!(settings.has_unsupported_feature());
        }
    }

    #[test]
    fn accepts_inactive_kcp_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","kcpSettings":{"mtu":1350,"tti":50,"header":{"type":"srtp"}}}"#,
            r#"{"network":"raw","kcpSettings":{"uplinkCapacity":5,"downlinkCapacity":20,"seed":"secret"}}"#,
            r#"{"kcpSettings":{"readBufferSize":2,"writeBufferSize":2,"congestion":true}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_kcp_stream_settings() {
        for kcp_settings in [
            r#"{"mtu":1349}"#,
            r#"{"mtu":1351}"#,
            r#"{"tti":49}"#,
            r#"{"tti":51}"#,
            r#"{"uplinkCapacity":6}"#,
            r#"{"downlinkCapacity":21}"#,
            r#"{"cwndMultiplier":2}"#,
            r#"{"maxSendingWindow":2097151}"#,
            r#"{"congestion":true}"#,
            r#"{"readBufferSize":2}"#,
            r#"{"writeBufferSize":2}"#,
            r#"{"header":{"type":"srtp"}}"#,
            r#"{"seed":"secret"}"#,
            r#"{"unknownKcpOption":true}"#,
            r#"{"unknownKcpOption":false}"#,
            r#"{"unknownKcpOption":0}"#,
            r#"{"unknownKcpOption":""}"#,
            r#"{"unknownKcpOption":{"key":"value"}}"#,
            r#"{"unknownKcpOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"kcp","kcpSettings":{kcp_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "kcp"
            ));
        }
    }

    #[test]
    fn parses_inert_quic_stream_settings() {
        for security in ["", "none"] {
            for (header, expected_header_type) in [
                ("{}", None),
                (r#"{"type":"none"}"#, Some("none")),
                (r#"{"type":"NONE"}"#, Some("NONE")),
            ] {
                for unknown_value in ["null", "{}", "[]"] {
                    let quic_settings = format!(
                        r#"{{"security":"{security}","key":"","header":{header},"unknownQuicOption":{unknown_value}}}"#
                    );
                    let json = format!(
                        r#"{{
                          "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"quicSettings":{quic_settings}}}}}],
                          "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"quicSettings":{{}}}}}}]
                        }}"#
                    );

                    let config: RootConfig = serde_json::from_str(&json).unwrap();
                    config.validate().unwrap();
                    let quic = config.inbounds[0]
                        .stream_settings
                        .as_ref()
                        .unwrap()
                        .quic_settings
                        .as_ref()
                        .unwrap();
                    let header = quic.header.as_ref().unwrap().as_object().unwrap();
                    assert_eq!(quic.security.as_deref(), Some(security));
                    assert_eq!(quic.key.as_deref(), Some(""));
                    assert_eq!(
                        header.get("type").and_then(Value::as_str),
                        expected_header_type
                    );
                    assert!(quic.extra.contains_key("unknownQuicOption"));
                }
            }
        }
    }

    #[test]
    fn accepts_inactive_quic_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","quicSettings":{"security":"aes-128-gcm","key":"secret","header":{"type":"srtp"}}}"#,
            r#"{"network":"raw","quicSettings":{"security":"aes-128-gcm","key":"secret","unknownQuicOption":{"key":"value"}}}"#,
            r#"{"quicSettings":{"security":"aes-128-gcm","key":"secret","unknownQuicOption":[true]}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_quic_stream_settings() {
        for quic_settings in [
            r#"{"security":"aes-128-gcm"}"#,
            r#"{"key":"secret"}"#,
            r#"{"header":{"type":"srtp"}}"#,
            r#"{"unknownQuicOption":true}"#,
            r#"{"unknownQuicOption":false}"#,
            r#"{"unknownQuicOption":0}"#,
            r#"{"unknownQuicOption":""}"#,
            r#"{"unknownQuicOption":{"key":"value"}}"#,
            r#"{"unknownQuicOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"quic","quicSettings":{quic_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "quic"
            ));
        }
    }

    #[test]
    fn parses_inert_domain_socket_stream_settings() {
        for (abstract_value, unknown_field) in [
            ("false", ""),
            ("null", ""),
            ("false", r#", "unknownDomainSocketOption":null"#),
            ("false", r#", "unknownDomainSocketOption":{}"#),
            ("false", r#", "unknownDomainSocketOption":[]"#),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"dsSettings":{{"path":"","abstract":{abstract_value},"padding":false{unknown_field}}}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"dsSettings":{{}}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let ds = config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .ds_settings
                .as_ref()
                .unwrap();
            assert_eq!(ds.path.as_deref(), Some(""));
            assert!(!ds.abstract_namespace);
            assert_eq!(ds.padding, Some(false));
        }
    }

    #[test]
    fn accepts_inactive_domain_socket_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","dsSettings":{"path":"/tmp/xray.sock","abstract":true}}"#,
            r#"{"network":"raw","dsSettings":{"padding":true}}"#,
            r#"{"dsSettings":{"unknownDomainSocketOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_domain_socket_stream_settings() {
        for ds_settings in [
            r#"{"path":"/tmp/xray.sock"}"#,
            r#"{"abstract":true}"#,
            r#"{"padding":true}"#,
            r#"{"unknownDomainSocketOption":true}"#,
            r#"{"unknownDomainSocketOption":false}"#,
            r#"{"unknownDomainSocketOption":0}"#,
            r#"{"unknownDomainSocketOption":""}"#,
            r#"{"unknownDomainSocketOption":{"key":"value"}}"#,
            r#"{"unknownDomainSocketOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"domainsocket","dsSettings":{ds_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "domainsocket"
            ));
        }
    }

    #[test]
    fn parses_inert_websocket_stream_settings() {
        for ws_settings in [
            r#"{}"#,
            r#"{"path":"","host":"","acceptProxyProtocol":false}"#,
            r#"{"acceptProxyProtocol":null}"#,
            r#"{"headers":null,"unknownWebSocketOption":null}"#,
            r#"{"headers":{}}"#,
            r#"{"headers":{"Host":null}}"#,
            r#"{"unknownWebSocketOption":{}}"#,
            r#"{"unknownWebSocketOption":[]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"wsSettings":{ws_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{{"wsSettings":{ws_settings}}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
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
    }

    #[test]
    fn accepts_inert_websocket_empty_host_header() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{"wsSettings":{"headers":{"Host":[]}}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"wsSettings":{"headers":{"Host":[]}}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_inactive_websocket_stream_settings_on_tcp_streams() {
        for stream_settings in [
            r#"{"network":"tcp","wsSettings":{"path":"/ws","host":"example.com"}}"#,
            r#"{"network":"raw","wsSettings":{"headers":{"Host":"example.com"},"acceptProxyProtocol":true}}"#,
            r#"{"wsSettings":{"unknownWebSocketOption":{"key":"value"}}}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{stream_settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","streamSettings":{stream_settings}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_websocket_stream_settings() {
        for ws_settings in [
            r#"{"path":"/ws"}"#,
            r#"{"host":"example.com"}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"acceptProxyProtocol":true}"#,
            r#"{"unknownWebSocketOption":true}"#,
            r#"{"unknownWebSocketOption":false}"#,
            r#"{"unknownWebSocketOption":0}"#,
            r#"{"unknownWebSocketOption":""}"#,
            r#"{"unknownWebSocketOption":{"key":"value"}}"#,
            r#"{"unknownWebSocketOption":[true]}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","streamSettings":{{"network":"ws","wsSettings":{ws_settings}}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTransportNetwork(network)) if network == "ws"
            ));
        }
    }

    #[test]
    fn accepts_sockopt_ip_if_non_match_domain_strategy() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":"IPIfNonMatch"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .sockopt
                .as_ref()
                .unwrap()
                .domain_strategy
                .as_deref(),
            Some("IPIfNonMatch")
        );
    }

    #[test]
    fn rejects_unsupported_sockopt_stream_settings() {
        for sockopt in [
            r#"{"mark":255}"#,
            r#"{"tproxy":"tproxy"}"#,
            r#"{"domainStrategy":"ForceIP"}"#,
            r#"{"dialerProxy":"proxy"}"#,
            r#"{"tcpMptcp":true}"#,
            r#"{"interface":"en0"}"#,
            r#"{"unknownSockoptOption":true}"#,
            r#"{"unknownSockoptOption":{"key":"value"}}"#,
            r#"{"unknownSockoptOption":[true]}"#,
        ] {
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
    fn accepts_empty_stream_network() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","streamSettings":{"network":""}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"network":""}}]
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
            Some("")
        );
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .network
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn accepts_empty_stream_security() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","streamSettings":{"security":""}}],
          "outbounds": [{"tag":"direct","protocol":"freedom","streamSettings":{"security":""}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.inbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .security
                .as_deref(),
            Some("")
        );
        assert_eq!(
            config.outbounds[0]
                .stream_settings
                .as_ref()
                .unwrap()
                .security
                .as_deref(),
            Some("")
        );
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

        let inbound_header = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"socks","streamSettings":{"tcpSettings":{"header":{"type":"http"}}}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;
        let config: RootConfig = serde_json::from_str(inbound_header).unwrap();
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
    fn rejects_nullable_inbound_proxy_auth_accounts_as_empty() {
        for account in [
            r#"{"user":null,"pass":"pass"}"#,
            r#"{"user":"user","pass":null}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"http-in","listen":"127.0.0.1","port":1080,"protocol":"http","settings":{{"accounts":[{account}]}}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidInboundAuthSettings)
            ));
        }
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
    fn parses_freedom_domain_strategy_settings() {
        for domain_strategy in ["UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"domainStrategy":"{domain_strategy}","targetStrategy":"{domain_strategy}"}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let settings = config.outbounds[0].settings.as_ref().unwrap();
            assert_eq!(settings.domain_strategy.as_deref(), Some(domain_strategy));
            assert_eq!(settings.target_strategy.as_deref(), Some(domain_strategy));
        }
    }

    #[test]
    fn rejects_unsupported_freedom_domain_strategy_settings() {
        for field in ["domainStrategy", "targetStrategy"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"{field}":"UseIPv8"}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedFreedomDomainStrategy(strategy)) if strategy == "UseIPv8"
            ));
        }
    }

    #[test]
    fn accepts_inert_non_freedom_domain_strategy_settings() {
        for field in ["domainStrategy", "targetStrategy"] {
            for value in ["", "AsIs"] {
                let json = format!(
                    r#"{{
                      "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                      "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"{field}":"{value}"}}}}]
                    }}"#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn rejects_non_freedom_domain_strategy_settings() {
        for field in ["domainStrategy", "targetStrategy"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"{field}":"UseIPv4"}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedOutboundSettingsField(value)) if value == field
            ));
        }
    }

    #[test]
    fn parses_freedom_proxy_protocol_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"proxyProtocol":1}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0]
                .settings
                .as_ref()
                .unwrap()
                .proxy_protocol,
            Some(1)
        );
    }

    #[test]
    fn rejects_unsupported_freedom_proxy_protocol_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"proxyProtocol":3}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedFreedomProxyProtocol(3))
        ));
    }

    #[test]
    fn rejects_non_freedom_proxy_protocol_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"proxyProtocol":1}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "proxyProtocol"
        ));
    }

    #[test]
    fn parses_freedom_user_level_zero_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"userLevel":0}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0].settings.as_ref().unwrap().user_level,
            Some(0)
        );
    }

    #[test]
    fn rejects_active_freedom_user_level_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"userLevel":1}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedFreedomUserLevel(1))
        ));
    }

    #[test]
    fn accepts_non_freedom_user_level_zero_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"userLevel":0}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.outbounds[0].settings.as_ref().unwrap().user_level,
            Some(0)
        );
    }

    #[test]
    fn rejects_non_freedom_user_level_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"userLevel":1}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "userLevel"
        ));
    }

    #[test]
    fn accepts_inert_freedom_fragment_settings() {
        for fragment in [
            "null",
            "{}",
            r#"{"packets":"","length":"","interval":""}"#,
            r#"{"packets":"0","length":"0","interval":"0"}"#,
            r#"{"packets":"0-0","length":"0-0","interval":"0-0"}"#,
            r#"{"packets":0,"length":0,"interval":0}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"fragment":{fragment}}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_freedom_fragment_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedFreedomFragment)
        ));
    }

    #[test]
    fn accepts_inert_non_freedom_fragment_settings() {
        for fragment in [
            "null",
            "{}",
            r#"{"packets":"","length":"","interval":""}"#,
            r#"{"packets":"0","length":"0","interval":"0"}"#,
            r#"{"packets":"0-0","length":"0-0","interval":"0-0"}"#,
            r#"{"packets":0,"length":0,"interval":0}"#,
        ] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"blocked","protocol":"blackhole","settings":{{"fragment":{fragment}}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_non_freedom_fragment_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"fragment":{"packets":"tlshello"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "fragment"
        ));
    }

    #[test]
    fn accepts_inert_freedom_noises_settings() {
        for noises in ["null", "[]"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"noises":{noises}}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_freedom_noises_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"noises":[{"type":"rand","packet":"base64,AA==","delay":"10"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedFreedomNoises)
        ));
    }

    #[test]
    fn rejects_non_freedom_noises_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"noises":[{"type":"rand"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "noises"
        ));
    }

    #[test]
    fn accepts_inert_freedom_final_rules_settings() {
        for final_rules in ["null", "[]"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"finalRules":{final_rules}}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_freedom_final_rules_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"type":"field","ip":["geoip:private"]}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedFreedomFinalRules)
        ));
    }

    #[test]
    fn rejects_non_freedom_final_rules_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"finalRules":[{"type":"field"}]}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "finalRules"
        ));
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
    fn accepts_empty_non_freedom_redirect_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"redirect":""}}]
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
            Some("")
        );
    }

    #[test]
    fn rejects_non_freedom_redirect_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"blocked","protocol":"blackhole","settings":{"redirect":"127.0.0.1:8080"}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "redirect"
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
    fn accepts_inert_non_blackhole_response_settings() {
        for response in ["null", "{}", r#"{"type":""}"#, r#"{"type":"none"}"#] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom","settings":{{"response":{response}}}}}]
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_non_blackhole_response_settings() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"response":{"type":"http"}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "response"
        ));
    }

    #[test]
    fn rejects_non_blackhole_response_extra_as_response_field() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
          "outbounds": [{"tag":"direct","protocol":"freedom","settings":{"response":{"type":"http","unknownResponseOption":true}}}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedOutboundSettingsField(field)) if field == "response"
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
    fn accepts_vless_inbound_none_decryption() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","listen":"127.0.0.1","port":1080,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_vless_non_none_decryption() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","port":1080,"protocol":"vless","settings":{"decryption":"aes-128-gcm","clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef"}]}}],
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
    fn accepts_empty_vless_inbound_client_flow() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","port":1080,"protocol":"vless","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef","flow":""}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_non_empty_vless_inbound_client_flow() {
        let json = r#"
        {
          "inbounds": [{"tag":"vless-in","port":1080,"protocol":"vless","settings":{"clients":[{"id":"01234567-89ab-cdef-0123-456789abcdef","flow":"xtls-rprx-vision"}]}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedInboundClientField(field)) if field == "flow"
        ));
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
    fn accepts_inert_non_dokodemo_inbound_target_settings() {
        for settings in [
            r#"{"address":""}"#,
            r#"{"port":0}"#,
            r#"{"address":"","port":0}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_non_dokodemo_inbound_target_settings() {
        for (settings, field) in [
            (r#"{"address":"127.0.0.1"}"#, "address"),
            (r#"{"port":80}"#, "port"),
            (r#"{"address":"127.0.0.1","port":80}"#, "address"),
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks","settings":{settings}}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedInboundSettingsField(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn rejects_zero_inbound_port_as_invalid_port() {
        for port in ["0", "null"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":{port},"protocol":"socks"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
        }
    }

    #[test]
    fn rejects_zero_dokodemo_target_port_as_invalid_port() {
        let json = r#"
        {
          "inbounds": [{"tag":"door","port":1080,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":0}}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
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
        for port in ["0", "null"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds": [{{"tag":"upstream","protocol":"http","settings":{{"servers":[{{"address":"127.0.0.1","port":{port}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
        }
    }

    #[test]
    fn rejects_dns_outbound_zero_server_port() {
        for port in ["0", "null"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"dns-in","port":1080,"protocol":"dokodemo-door","settings":{{"address":"1.1.1.1","port":53}}}}],
                  "outbounds": [{{"tag":"dns-out","protocol":"dns","settings":{{"servers":[{{"address":"127.0.0.1","port":{port}}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(config.validate(), Err(ConfigError::InvalidPort)));
        }
    }

    #[test]
    fn rejects_dns_outbound_invalid_server_address() {
        for address in [r#""""#, "null"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"dns-in","port":1080,"protocol":"dokodemo-door","settings":{{"address":"1.1.1.1","port":53}}}}],
                  "outbounds": [{{"tag":"dns-out","protocol":"dns","settings":{{"servers":[{{"address":{address},"port":53}}]}}}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::MissingProxyServer)
            ));
        }
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
    fn accepts_nullable_top_level_endpoint_lists_as_empty() {
        let json = r#"
        {
          "inbounds": null,
          "outbounds": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(config.inbounds.is_empty());
        assert!(config.outbounds.is_empty());
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingInbound)
        ));
    }

    #[test]
    fn accepts_nullable_top_level_outbounds_as_empty() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": null
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(config.outbounds.is_empty());
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingOutbound)
        ));
    }

    #[test]
    fn accepts_empty_top_level_version_settings() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "version": {}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.version, Some(serde_json::json!({})));
    }

    #[test]
    fn accepts_top_level_version_settings() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "version": {"min":"0.1.0"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.version, Some(serde_json::json!({"min": "0.1.0"})));
    }

    #[test]
    fn accepts_inert_unknown_top_level_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "unknownRootOption": {unknown_value}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(config.extra.contains_key("unknownRootOption"));
        }
    }

    #[test]
    fn rejects_active_unknown_top_level_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "unknownRootOption": {unknown_value}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedTopLevelField(field)) if field == "unknownRootOption"
            ));
        }
    }

    #[test]
    fn merged_inert_unknown_top_level_fields_are_rejected_when_overridden_by_active_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "inbounds":[{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds":[{{"tag":"direct","protocol":"freedom"}}],
                  "unknownRootOption": {unknown_value}
                }}"#,
            ))
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
    }

    #[test]
    fn merged_active_unknown_top_level_fields_cannot_be_cleared_by_inert_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "unknownRootOption": true
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "unknownRootOption": {unknown_value}
                }}"#,
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedTopLevelField(field)) if field == "unknownRootOption"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_routing_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"unknownRoutingOption": {unknown_value}}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(config.routing.extra.contains_key("unknownRoutingOption"));
        }
    }

    #[test]
    fn rejects_active_unknown_routing_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"unknownRoutingOption": {unknown_value}}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedRoutingField(field)) if field == "unknownRoutingOption"
            ));
        }
    }

    #[test]
    fn merged_inert_unknown_routing_fields_are_rejected_when_overridden_by_active_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "inbounds":[{{"tag":"socks-in","port":1080,"protocol":"socks"}}],
                  "outbounds":[{{"tag":"direct","protocol":"freedom"}}],
                  "routing":{{"unknownRoutingOption":{unknown_value}}}
                }}"#,
            ))
            .unwrap();
            let second: RootConfig = serde_json::from_str(
                r#"{
                  "routing":{"unknownRoutingOption":true}
                }"#,
            )
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedRoutingField(field)) if field == "unknownRoutingOption"
            ));
        }
    }

    #[test]
    fn merged_active_unknown_routing_fields_cannot_be_cleared_by_inert_values() {
        for unknown_value in ["null", "{}", "[]"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "routing":{"unknownRoutingOption":true}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "routing":{{"unknownRoutingOption":{unknown_value}}}
                }}"#,
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedRoutingField(field)) if field == "unknownRoutingOption"
            ));
        }
    }

    #[test]
    fn accepts_runtime_supported_routing_domain_matcher_modes() {
        for mode in ["", "linear", "mph"] {
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
    fn accepts_routing_domain_matcher_hybrid() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"domainMatcher": "hybrid"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.domain_matcher.as_deref(), Some("hybrid"));
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
    fn merged_active_routing_domain_matcher_cannot_be_cleared_by_supported_value() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "routing":{"domainMatcher":"unknown"}
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
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedRoutingDomainMatcher(value)) if value == "unknown"
        ));
    }

    #[test]
    fn merged_active_routing_domain_matcher_overrides_supported_value() {
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
        for domain_strategy in ["", "AsIs", "IPIfNonMatch", "IPOnDemand", "UseIP"] {
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
    fn accepts_routing_domain_strategy_use_ipv4() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"domainStrategy": "UseIPv4"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.domain_strategy.as_deref(), Some("UseIPv4"));
    }

    #[test]
    fn accepts_routing_domain_strategy_use_ipv6() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"domainStrategy": "UseIPv6"}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.domain_strategy.as_deref(), Some("UseIPv6"));
    }

    #[test]
    fn accepts_routing_domain_strategy_dual_family_values() {
        for domain_strategy in ["UseIPv4v6", "UseIPv6v4"] {
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
    fn merged_routing_domain_strategy_use_ipv4_is_accepted() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"domainStrategy":"UseIPv4"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.routing.domain_strategy.as_deref(), Some("UseIPv4"));
    }

    #[test]
    fn merged_active_routing_domain_strategy_use_ipv4_cannot_be_cleared_by_default_value() {
        for domain_strategy in ["AsIs", "UseIP"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "routing":{"domainStrategy":"UseIPv4"}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "routing":{{"domainStrategy":"{domain_strategy}"}}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            first.validate().unwrap();
            assert_eq!(first.routing.domain_strategy.as_deref(), Some("UseIPv4"));
        }
    }

    #[test]
    fn merged_active_routing_domain_strategy_use_ipv6_cannot_be_cleared_by_default_value() {
        for domain_strategy in ["AsIs", "UseIP"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "routing":{"domainStrategy":"UseIPv6"}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "routing":{{"domainStrategy":"{domain_strategy}"}}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            first.validate().unwrap();
            assert_eq!(first.routing.domain_strategy.as_deref(), Some("UseIPv6"));
        }
    }

    #[test]
    fn merged_active_routing_domain_strategy_overrides_supported_value() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "routing":{"domainStrategy":"AsIs"}
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"domainStrategy":"UseIPv4"}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.routing.domain_strategy.as_deref(), Some("UseIPv4"));
    }

    #[test]
    fn merged_unsupported_routing_domain_strategy_cannot_be_cleared_by_ip_family_values() {
        for domain_strategy in ["UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4"] {
            let mut first: RootConfig = serde_json::from_str(
                r#"{
                  "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
                  "outbounds":[{"tag":"direct","protocol":"freedom"}],
                  "routing":{"domainStrategy":"unsupported"}
                }"#,
            )
            .unwrap();
            let second: RootConfig = serde_json::from_str(&format!(
                r#"{{
                  "routing":{{"domainStrategy":"{domain_strategy}"}}
                }}"#
            ))
            .unwrap();

            first.merge(second);
            assert!(matches!(
                first.validate(),
                Err(ConfigError::UnsupportedRoutingDomainStrategyFeature)
            ));
            assert_eq!(
                first.routing.domain_strategy.as_deref(),
                Some("unsupported")
            );
        }
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
    fn accepts_nullable_routing_slice_defaults() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": null, "balancers": null}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert!(config.routing.rules.is_empty());
        assert!(config.routing.balancers.is_empty());
    }

    #[test]
    fn accepts_supported_routing_balancers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":["direct"]}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.balancers[0].tag, "auto");
        assert_eq!(
            config.routing.balancers[0].selector,
            vec!["direct".to_owned()]
        );
    }

    #[test]
    fn rejects_nullable_routing_balancer_tag_as_empty() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":null,"selector":["direct"]}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyTag { kind: "balancer" })
        ));
    }

    #[test]
    fn accepts_random_routing_balancer_strategy() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
          "routing": {"balancers": [{"tag":"auto","selector":["direct","blocked"],"strategy":{"type":"random"}}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_least_ping_routing_balancer_strategy() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct-a","protocol":"freedom"},{"tag":"direct-b","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":["direct-"],"strategy":{"type":"leastPing"}}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_empty_routing_balancer_strategy() {
        for strategy in [r#"{}"#, r#"{"type":""}"#] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"balancers": [{{"tag":"auto","selector":["direct"],"strategy":{strategy}}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            let strategy = config.routing.balancers[0].strategy.as_ref().unwrap();
            assert!(strategy.strategy_type.as_deref().is_none_or(str::is_empty));
        }
    }

    #[test]
    fn accepts_routing_balancer_prefix_selectors() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"proxy-a","protocol":"freedom"},{"tag":"proxy-b","protocol":"freedom"},{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":["proxy-"],"fallbackTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn accepts_inert_routing_balancer_without_selector_or_fallback() {
        for balancer in [
            r#"{"tag":"auto"}"#,
            r#"{"tag":"auto","selector":[]}"#,
            r#"{"tag":"auto","selector":null}"#,
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"balancers": [{balancer}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert_eq!(config.routing.balancers[0].tag, "auto");
            assert!(config.routing.balancers[0].selector.is_empty());
            assert!(config.routing.balancers[0].fallback_tag.is_none());
        }
    }

    #[test]
    fn accepts_null_routing_balancer_selector_with_fallback() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":null,"fallbackTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.balancers[0].tag, "auto");
        assert!(config.routing.balancers[0].selector.is_empty());
        assert_eq!(
            config.routing.balancers[0].fallback_tag.as_deref(),
            Some("direct")
        );
    }

    #[test]
    fn merged_routing_balancers_are_accepted() {
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
        first.validate().unwrap();
        assert_eq!(first.routing.balancers[0].tag, "auto");
    }

    #[test]
    fn rejects_active_unknown_routing_balancer_fields() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"balancers": [{"tag":"auto","selector":["direct"],"strategy":{"type":"random","settings":{"observe":true}}}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedRoutingField(field)) if field == "strategy"
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
    fn accepts_null_routing_rule_matcher_lists() {
        let json = r#"
        {
          "inbounds": [{"tag":"http-in","port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"outboundTag":"direct","inboundTag":null,"domain":null,"ip":null,"protocol":null,"user":null}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        let rule = &config.routing.rules[0];
        assert!(rule.inbound_tag.is_empty());
        assert!(rule.domain.is_empty());
        assert!(rule.ip.is_empty());
        assert!(rule.protocol.is_empty());
        assert!(rule.user.is_empty());
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
    fn accepts_empty_routing_rule_type() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"type":"","outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.routing.rules[0].rule_type.as_deref(), Some(""));
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
    fn accepts_routing_rule_balancer_targets() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {
            "balancers": [{"tag":"auto","selector":["direct"]}],
            "rules": [{"balancerTag":"auto"}]
          }
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.routing.rules[0].balancer_tag.as_deref(),
            Some("auto")
        );
        config.validate().unwrap();
    }

    #[test]
    fn accepts_routing_rule_http_protocol_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"protocol":["http"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.routing.rules[0].protocol, vec!["http".to_owned()]);
        config.validate().unwrap();
    }

    #[test]
    fn accepts_routing_rule_tls_protocol_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"protocol":["tls"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.routing.rules[0].protocol, vec!["tls".to_owned()]);
        config.validate().unwrap();
    }

    #[test]
    fn accepts_routing_rule_quic_protocol_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"protocol":["quic"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.routing.rules[0].protocol, vec!["quic".to_owned()]);
        config.validate().unwrap();
    }

    #[test]
    fn accepts_empty_routing_rule_protocol_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"protocol":[""],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.routing.rules[0].protocol, vec!["".to_owned()]);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_routing_rule_protocol_matchers() {
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
    fn accepts_routing_rule_user_matchers() {
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
        config.validate().unwrap();
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
    fn accepts_inert_routing_rule_attrs() {
        for attrs in ["null", "\"\"", "[]", "{}"] {
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":{attrs}}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_routing_rule_http_method_attrs_matcher() {
        for method in ["GET", "POST"] {
            for attrs in [
                format!("attrs[':method'] == '{method}'"),
                format!("attrs[':method'] == \"{method}\""),
                format!("attrs[\":method\"] == '{method}'"),
                format!("attrs[\":method\"] == \"{method}\""),
            ] {
                let escaped_attrs = attrs.replace('"', "\\\"");
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"port":1080,"protocol":"http"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                    }}
                    "#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), &attrs);
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_routing_rule_http_method_inequality_attrs_matcher() {
        for method in ["GET", "POST"] {
            for attrs in [
                format!("attrs[':method'] != '{method}'"),
                format!("attrs[':method'] != \"{method}\""),
                format!("attrs[\":method\"] != '{method}'"),
                format!("attrs[\":method\"] != \"{method}\""),
            ] {
                let escaped_attrs = attrs.replace('"', "\\\"");
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"port":1080,"protocol":"http"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                    }}
                    "#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), &attrs);
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_routing_rule_http_path_attrs_matcher() {
        for path in ["/", "/blocked"] {
            for attrs in [
                format!("attrs[':path'] == '{path}'"),
                format!("attrs[':path'] == \"{path}\""),
                format!("attrs[\":path\"] == '{path}'"),
                format!("attrs[\":path\"] == \"{path}\""),
            ] {
                let escaped_attrs = attrs.replace('"', "\\\"");
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"port":1080,"protocol":"http"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                    }}
                    "#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), &attrs);
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_routing_rule_http_path_inequality_attrs_matcher() {
        for path in ["/", "/blocked"] {
            for attrs in [
                format!("attrs[':path'] != '{path}'"),
                format!("attrs[':path'] != \"{path}\""),
                format!("attrs[\":path\"] != '{path}'"),
                format!("attrs[\":path\"] != \"{path}\""),
            ] {
                let escaped_attrs = attrs.replace('"', "\\\"");
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"port":1080,"protocol":"http"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                    }}
                    "#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), &attrs);
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_routing_rule_http_path_prefix_attrs_matcher() {
        for prefix in ["/", "/blocked"] {
            for attrs in [
                format!("attrs[':path'].startswith('{prefix}')"),
                format!("attrs[':path'].startswith(\"{prefix}\")"),
                format!("attrs[\":path\"].startswith('{prefix}')"),
                format!("attrs[\":path\"].startswith(\"{prefix}\")"),
            ] {
                let escaped_attrs = attrs.replace('"', "\\\"");
                let json = format!(
                    r#"
                    {{
                      "inbounds": [{{"port":1080,"protocol":"http"}}],
                      "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                      "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                    }}
                    "#
                );

                let config: RootConfig = serde_json::from_str(&json).unwrap();
                assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), &attrs);
                config.validate().unwrap();
            }
        }
    }

    #[test]
    fn accepts_routing_rule_http_path_contains_attrs_matcher() {
        for attrs in [
            "attrs[':path'].contains('/ads')",
            "attrs[':path'].contains(\"/ads\")",
            "attrs[\":path\"].contains('/ads')",
            "attrs[\":path\"].contains(\"/ads\")",
        ] {
            let escaped_attrs = attrs.replace('"', "\\\"");
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), attrs);
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_routing_rule_compound_http_attrs_matcher() {
        for attrs in [
            "attrs[':method'] == 'GET' && attrs[':path'] == '/blocked'",
            "attrs[':method'] == \"GET\" && attrs[':path'] == \"/blocked\"",
            "attrs[':path'] == '/blocked' && attrs[':method'] == 'GET'",
            "attrs[':path'] == \"/blocked\" && attrs[':method'] == \"GET\"",
            "attrs[':method'] == 'GET' && attrs[':path'].startswith('/blocked')",
            "attrs[':method'] == \"GET\" && attrs[':path'].startswith(\"/blocked\")",
            "attrs[':path'].startswith('/blocked') && attrs[':method'] == 'GET'",
            "attrs[':path'].startswith(\"/blocked\") && attrs[':method'] == \"GET\"",
            "attrs[\":method\"] == \"GET\" && attrs[\":path\"].startswith(\"/blocked\")",
            "attrs[\":path\"].startswith(\"/blocked\") && attrs[\":method\"] == \"GET\"",
            "attrs[':method'] != 'GET' && attrs[':path'] == '/blocked'",
            "attrs[':path'] == '/blocked' && attrs[':method'] != 'GET'",
            "attrs[':method'] != \"GET\" && attrs[':path'] == \"/blocked\"",
            "attrs[':path'] == \"/blocked\" && attrs[':method'] != \"GET\"",
            "attrs[':method'] != 'GET' && attrs[':path'].startswith('/blocked')",
            "attrs[':path'].startswith('/blocked') && attrs[':method'] != 'GET'",
            "attrs[':method'] != \"GET\" && attrs[':path'].startswith(\"/blocked\")",
            "attrs[':path'].startswith(\"/blocked\") && attrs[':method'] != \"GET\"",
            "attrs[\":method\"] != \"GET\" && attrs[\":path\"].startswith(\"/blocked\")",
            "attrs[\":path\"].startswith(\"/blocked\") && attrs[\":method\"] != \"GET\"",
            "attrs[':method'] == 'GET' && attrs[':path'] != '/blocked'",
            "attrs[':path'] != '/blocked' && attrs[':method'] == 'GET'",
            "attrs[':method'] == \"GET\" && attrs[':path'] != \"/blocked\"",
            "attrs[':path'] != \"/blocked\" && attrs[':method'] == \"GET\"",
            "attrs[\":method\"] == \"GET\" && attrs[\":path\"] != \"/blocked\"",
            "attrs[\":path\"] != \"/blocked\" && attrs[\":method\"] == \"GET\"",
            "attrs[':method'] == 'GET' && attrs[':path'].startswith('/api') && attrs[':path'].contains('/v1')",
            "attrs[':path'].startswith('/api') && attrs[':method'] == 'GET' && attrs[':path'].contains('/v1')",
        ] {
            let escaped_attrs = attrs.replace('"', "\\\"");
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), attrs);
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_routing_rule_or_http_attrs_matcher() {
        for attrs in [
            "attrs[':method'] == 'GET' || attrs[':method'] == 'POST'",
            "attrs[':method'] == \"GET\" || attrs[':method'] == \"POST\"",
            "attrs[':method'] == 'GET' || attrs[':path'] == '/blocked'",
            "attrs[':path'] == '/blocked' || attrs[':method'] == 'GET'",
            "attrs[':path'] == '/blocked' || attrs[':path'].startswith('/ads')",
            "attrs[\":method\"] == \"GET\" || attrs[\":path\"] == \"/blocked\"",
            "attrs[':method'] == 'GET' || attrs[':method'] == 'POST' || attrs[':method'] == 'PUT'",
            "attrs[':path'] == '/blocked' || attrs[':path'].startswith('/ads') || attrs[':path'].contains('/track')",
        ] {
            let escaped_attrs = attrs.replace('"', "\\\"");
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), attrs);
            config.validate().unwrap();
        }
    }

    #[test]
    fn accepts_routing_rule_parenthesized_http_attrs_matcher() {
        for attrs in [
            "(attrs[':method'] == 'GET')",
            "(attrs[':method'] == 'GET') || (attrs[':method'] == 'POST')",
            "(attrs[':method'] == 'POST') && (attrs[':path'].startswith('/api/'))",
            "(attrs[':path'] == '/blocked') || (attrs[':path'].startswith('/ads'))",
        ] {
            let escaped_attrs = attrs.replace('"', "\\\"");
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config.routing.rules[0].attrs.as_ref().unwrap(), attrs);
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_routing_rule_attrs_matchers() {
        for attrs in [
            "attrs[':method'] == ''",
            "attrs[':method'] == 'GE'T'",
            "attrs[':method'] != 'GE'T'",
            r#"attrs[":method"] == "GE"T""#,
            r#"attrs[":method"] != "GE"T""#,
            "attrs[':path'] == 'blo'cked'",
            "attrs[':path'] != 'blo'cked'",
            r#"attrs[":path"] == "blo"cked""#,
            r#"attrs[":path"] != "blo"cked""#,
            "attrs[':path'].startswith('')",
            "attrs[':path'].startswith('/blocked'",
            "attrs[':path'].startsWith('/blocked')",
            "attrs[':path'].startswith('/blocked'))",
            "attrs[':method'] == 'GET' && attrs[':method'] == 'POST'",
            "attrs[':path'] == '/blocked' && attrs[':path'] == '/other'",
        ] {
            let escaped_attrs = attrs.replace('"', "\\\"");
            let json = format!(
                r#"
                {{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","attrs":"{escaped_attrs}"}}]}}
                }}
                "#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "attrs"
            ));
        }
    }

    #[test]
    fn rejects_active_unknown_routing_rule_fields() {
        for unknown_value in [
            "true",
            "false",
            "0",
            r#""""#,
            r#"{"key":"value"}"#,
            "[true]",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","unknown":{unknown_value}}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "unknown"
            ));
        }
    }

    #[test]
    fn accepts_inert_unknown_routing_rule_fields() {
        for unknown_value in ["null", "{}", "[]"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","unknown":{unknown_value}}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            config.validate().unwrap();
            assert!(config.routing.rules[0].extra.contains_key("unknown"));
        }
    }

    #[test]
    fn merged_unknown_routing_rule_fields_are_rejected() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "inbounds":[{"port":1080,"protocol":"http"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "routing":{"rules":[{"outboundTag":"direct","unknown":"tcp"}]}
            }"#,
        )
        .unwrap();

        first.merge(second);
        assert!(matches!(
            first.validate(),
            Err(ConfigError::UnsupportedRoutingRuleField(name)) if name == "unknown"
        ));
    }

    #[test]
    fn accepts_routing_rule_domain_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","domain":["example.com","full:api.example.com","domain:example.org","keyword:cdn","regexp:^api-[0-9]+\\.example\\.com$","geosite:private","geosite:cn"]}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_routing_rule_domain_matchers() {
        for domain in [
            "",
            "   ",
            "full:",
            "domain:",
            "keyword:",
            "regexp:",
            "geosite:",
            "full: example.com",
            "domain: example.com",
            "keyword: cdn",
            "regexp: ^example",
            "geosite: private",
            " example.com",
            "example.com ",
            "\\texample.com",
            "regexp:[",
            "geosite:us",
        ] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","domain":["{domain}"]}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingRuleDomainMatcher { .. })
            ));
        }
    }

    #[test]
    fn accepts_routing_rule_ip_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","ip":["127.0.0.1","192.0.2.0/24","geoip:private","geoip:cn"]}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_routing_rule_ip_matchers() {
        for ip in ["not-ip", "192.0.2.0/33", "geoip:us"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","ip":["{ip}"]}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingRuleIpMatcher { value, .. }) if value == ip
            ));
        }
    }

    #[test]
    fn accepts_routing_source_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","source":["127.0.0.1","192.0.2.0/24","geoip:private","geoip:cn"]}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0].source,
            vec![
                "127.0.0.1".to_owned(),
                "192.0.2.0/24".to_owned(),
                "geoip:private".to_owned(),
                "geoip:cn".to_owned()
            ]
        );
    }

    #[test]
    fn rejects_invalid_routing_source_matchers() {
        for source in ["not-ip", "geoip:us"] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"direct","source":["{source}"]}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRoutingSourceMatcher { value, .. }) if value == source
            ));
        }
    }

    #[test]
    fn accepts_routing_network_matchers() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","network":"tcp"},
            {"outboundTag":"direct","network":"tcp,udp"},
            {"outboundTag":"direct","network":"tcp,"},
            {"outboundTag":"direct","network":"tcp,,udp"},
            {"outboundTag":"direct","network":"quic"},
            {"outboundTag":"direct","network":"tcp,quic"}
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
            vec![RoutingNetwork::Tcp]
        );
        assert_eq!(
            config.routing.rules[1]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![RoutingNetwork::Tcp, RoutingNetwork::Udp]
        );
        assert_eq!(
            config.routing.rules[2]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![RoutingNetwork::Tcp]
        );
        assert_eq!(
            config.routing.rules[3]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![RoutingNetwork::Tcp, RoutingNetwork::Udp]
        );
        assert_eq!(
            config.routing.rules[4]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![RoutingNetwork::Quic]
        );
        assert_eq!(
            config.routing.rules[5]
                .network
                .as_ref()
                .unwrap()
                .networks()
                .unwrap(),
            vec![RoutingNetwork::Tcp, RoutingNetwork::Quic]
        );
    }

    #[test]
    fn rejects_invalid_routing_network_matchers() {
        for network in ["", "grpc", "tcp,grpc"] {
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
    fn accepts_routing_port_matchers_with_empty_segments() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","port":"8000-8999,,9443,"}
          ]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.routing.rules[0]
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
    fn accepts_routing_source_port_matchers_with_empty_segments() {
        let json = r#"
        {
          "inbounds": [{"port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [
            {"outboundTag":"direct","sourcePort":"40000-49999,,53000,"}
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
                .ranges()
                .unwrap(),
            vec![
                RoutingPortRange {
                    start: 40000,
                    end: 49999
                },
                RoutingPortRange {
                    start: 53000,
                    end: 53000
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
    fn accepts_known_routing_inbound_tags() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"inboundTag":["socks-in"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_blank_inbound_tags() {
        for tag in ["", "   "] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"{tag}","port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyTag { kind: "inbound" })
            ));
        }
    }

    #[test]
    fn rejects_duplicate_inbound_tags() {
        let json = r#"
        {
          "inbounds": [
            {"tag":"socks-in","port":1080,"protocol":"socks"},
            {"tag":"socks-in","port":1081,"protocol":"http"}
          ],
          "outbounds": [{"tag":"direct","protocol":"freedom"}]
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateTag { kind: "inbound", tag }) if tag == "socks-in"
        ));
    }

    #[test]
    fn rejects_blank_routing_inbound_tags() {
        for tag in ["", "   "] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"inboundTag":["{tag}"],"outboundTag":"direct"}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyTag { kind: "inbound" })
            ));
        }
    }

    #[test]
    fn rejects_unknown_routing_inbound_tags() {
        let json = r#"
        {
          "inbounds": [{"tag":"socks-in","port":1080,"protocol":"http"}],
          "outbounds": [{"tag":"direct","protocol":"freedom"}],
          "routing": {"rules": [{"inboundTag":["missing-in"],"outboundTag":"direct"}]}
        }
        "#;

        let config: RootConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownInboundTag(tag)) if tag == "missing-in"
        ));
    }

    #[test]
    fn rejects_blank_routing_outbound_tags() {
        for tag in ["", "   "] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"tag":"socks-in","port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
                  "routing": {{"rules": [{{"outboundTag":"{tag}"}}]}}
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyTag { kind: "outbound" })
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
    fn rejects_blank_outbound_tags() {
        for tag in ["", "   "] {
            let json = format!(
                r#"{{
                  "inbounds": [{{"port":1080,"protocol":"http"}}],
                  "outbounds": [{{"tag":"{tag}","protocol":"freedom"}}]
                }}"#
            );

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyTag { kind: "outbound" })
            ));
        }
    }

    #[test]
    fn rejects_nullable_endpoint_tags_as_empty() {
        for (kind, inbounds, outbounds) in [
            (
                "inbound",
                r#"[{"tag":null,"port":1080,"protocol":"http"}]"#,
                r#"[{"tag":"direct","protocol":"freedom"}]"#,
            ),
            (
                "outbound",
                r#"[{"port":1080,"protocol":"http"}]"#,
                r#"[{"tag":null,"protocol":"freedom"}]"#,
            ),
        ] {
            let json = format!(r#"{{"inbounds":{inbounds},"outbounds":{outbounds}}}"#);

            let config: RootConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyTag { kind: rejected }) if rejected == kind
            ));
        }
    }

    #[test]
    fn merges_config_fragments_in_order() {
        let mut first: RootConfig = serde_json::from_str(
            r#"{
              "log":{"level":"warning"},
              "inbounds":[{"tag":"socks-in","port":1080,"protocol":"socks"}],
              "outbounds":[{"tag":"direct","protocol":"freedom"}],
              "version":[]
            }"#,
        )
        .unwrap();
        let second: RootConfig = serde_json::from_str(
            r#"{
              "log":{"level":"debug"},
              "outbounds":[{"tag":"blocked","protocol":"blackhole"}],
              "routing":{"rules":[{"inboundTag":["socks-in"],"outboundTag":"blocked"}]},
              "version":{}
            }"#,
        )
        .unwrap();

        first.merge(second);
        first.validate().unwrap();
        assert_eq!(first.log.level, "debug");
        assert_eq!(first.inbounds.len(), 1);
        assert_eq!(first.outbounds.len(), 2);
        assert_eq!(first.routing.rules.len(), 1);
        assert_eq!(first.version.unwrap(), serde_json::json!({}));
    }
}
