#![forbid(unsafe_code)]

use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use thiserror::Error;
use xrs_common::{DestinationHost, Network, SessionContext};
use xrs_config::{ConfigError, RootConfig, RoutingPortRange, RoutingRuleConfig};

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("router requires at least one outbound")]
    MissingDefaultOutbound,
    #[error("invalid IP routing matcher {value}: {reason}")]
    InvalidIpMatcher { value: String, reason: String },
    #[error("invalid domain routing matcher {value}: {reason}")]
    InvalidDomainMatcher { value: String, reason: String },
    #[error(transparent)]
    InvalidRoutingMatcher(#[from] ConfigError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingDomainStrategy {
    AsIs,
    IpIfNonMatch,
}

#[derive(Clone, Debug)]
pub struct Router {
    default_outbound: String,
    domain_strategy: RoutingDomainStrategy,
    rules: Vec<RouteRule>,
}

impl Router {
    pub fn from_config(config: &RootConfig) -> Result<Self, RouterError> {
        let default_outbound = config
            .outbounds
            .first()
            .map(|outbound| outbound.tag.clone())
            .ok_or(RouterError::MissingDefaultOutbound)?;
        let rules = config
            .routing
            .rules
            .iter()
            .map(RouteRule::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            default_outbound,
            domain_strategy: RoutingDomainStrategy::from_config(
                config.routing.domain_strategy.as_deref(),
            ),
            rules,
        })
    }

    #[must_use]
    pub fn pick_outbound<'a>(&'a self, session: &SessionContext) -> &'a str {
        self.pick_rule_outbound(session)
            .unwrap_or(self.default_outbound.as_str())
    }

    #[must_use]
    pub fn pick_rule_outbound<'a>(&'a self, session: &SessionContext) -> Option<&'a str> {
        self.rules
            .iter()
            .find(|rule| rule.matches(session))
            .map(|rule| rule.outbound_tag.as_str())
    }

    #[must_use]
    pub fn pick_rule_outbound_for_any<'a>(
        &'a self,
        sessions: &[SessionContext],
    ) -> Option<&'a str> {
        self.rules
            .iter()
            .find(|rule| sessions.iter().any(|session| rule.matches(session)))
            .map(|rule| rule.outbound_tag.as_str())
    }

    #[must_use]
    pub fn default_outbound(&self) -> &str {
        self.default_outbound.as_str()
    }

    #[must_use]
    pub fn domain_strategy(&self) -> RoutingDomainStrategy {
        self.domain_strategy
    }
}

impl RoutingDomainStrategy {
    fn from_config(value: Option<&str>) -> Self {
        match value {
            Some("IPIfNonMatch") => Self::IpIfNonMatch,
            _ => Self::AsIs,
        }
    }
}

#[derive(Clone, Debug)]
struct RouteRule {
    inbound_tag: Vec<String>,
    port: Vec<RoutingPortRange>,
    network: Vec<Network>,
    domain: Vec<DomainMatcher>,
    ip: Vec<IpMatcher>,
    source: Vec<IpMatcher>,
    source_port: Vec<RoutingPortRange>,
    outbound_tag: String,
}

impl RouteRule {
    fn matches(&self, session: &SessionContext) -> bool {
        let inbound_matches = self.inbound_tag.is_empty()
            || self
                .inbound_tag
                .iter()
                .any(|tag| tag == &session.inbound_tag);
        let port_matches = self.port.is_empty()
            || self
                .port
                .iter()
                .any(|range| range.contains(session.destination.port));
        let network_matches =
            self.network.is_empty() || self.network.contains(&session.destination.network);
        let domain_matches = self.domain.is_empty()
            || match &session.destination.host {
                DestinationHost::Domain(domain) => {
                    self.domain.iter().any(|matcher| matcher.matches(domain))
                }
                DestinationHost::Ip(_) => false,
            };
        let ip_matches = self.ip.is_empty()
            || match session.destination.host {
                DestinationHost::Ip(ip) => self.ip.iter().any(|matcher| matcher.matches(ip)),
                DestinationHost::Domain(_) => false,
            };
        let source_matches = self.source.is_empty()
            || session
                .source_ip
                .is_some_and(|ip| self.source.iter().any(|matcher| matcher.matches(ip)));
        let source_port_matches = self.source_port.is_empty()
            || session
                .source_port
                .is_some_and(|port| self.source_port.iter().any(|range| range.contains(port)));

        inbound_matches
            && port_matches
            && network_matches
            && domain_matches
            && ip_matches
            && source_matches
            && source_port_matches
    }
}

impl TryFrom<&RoutingRuleConfig> for RouteRule {
    type Error = RouterError;

    fn try_from(value: &RoutingRuleConfig) -> Result<Self, Self::Error> {
        let domain = value
            .domain
            .iter()
            .map(|matcher| DomainMatcher::parse(matcher))
            .collect::<Result<Vec<_>, _>>()?;
        let ip = value
            .ip
            .iter()
            .map(|matcher| IpMatcher::parse(matcher))
            .collect::<Result<Vec<_>, _>>()?;
        let source = value
            .source
            .iter()
            .map(|matcher| IpMatcher::parse(matcher))
            .collect::<Result<Vec<_>, _>>()?;
        let port = value
            .port
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |matcher| matcher.ranges())?;
        let source_port = value
            .source_port
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |matcher| matcher.ranges())?;
        let network = value
            .network
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |matcher| matcher.networks())?;

        Ok(Self {
            inbound_tag: value.inbound_tag.clone(),
            port,
            network,
            domain,
            ip,
            source,
            source_port,
            outbound_tag: value.outbound_tag.clone().ok_or_else(|| {
                RouterError::InvalidRoutingMatcher(ConfigError::UnsupportedRoutingRuleField(
                    "outboundTag".to_owned(),
                ))
            })?,
        })
    }
}

#[derive(Clone, Debug)]
enum DomainMatcher {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regexp(Regex),
    GeositePrivate,
}

impl DomainMatcher {
    fn parse(value: &str) -> Result<Self, RouterError> {
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(full) = value.strip_prefix("full:") {
            Ok(Self::Full(full.to_owned()))
        } else if let Some(suffix) = value.strip_prefix("domain:") {
            Ok(Self::Suffix(suffix.to_owned()))
        } else if let Some(keyword) = value.strip_prefix("keyword:") {
            Ok(Self::Keyword(keyword.to_owned()))
        } else if let Some(pattern) = value.strip_prefix("regexp:") {
            Regex::new(pattern).map(Self::Regexp).map_err(|source| {
                RouterError::InvalidDomainMatcher {
                    value,
                    reason: source.to_string(),
                }
            })
        } else if let Some(name) = value.strip_prefix("geosite:") {
            match name {
                "private" => Ok(Self::GeositePrivate),
                _ => Err(RouterError::InvalidDomainMatcher {
                    value,
                    reason: "unsupported geosite list".to_owned(),
                }),
            }
        } else {
            Ok(Self::Suffix(value))
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        match self {
            Self::Full(full) => domain == *full,
            Self::Suffix(suffix) => domain == *suffix || domain.ends_with(&format!(".{suffix}")),
            Self::Keyword(keyword) => domain.contains(keyword),
            Self::Regexp(pattern) => pattern.is_match(&domain),
            Self::GeositePrivate => is_private_geosite_domain(&domain),
        }
    }
}

fn is_private_geosite_domain(domain: &str) -> bool {
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
            .any(|suffix| domain_matches_suffix(domain, suffix))
        || matches_private_reverse_dns_range(domain)
        || matches_dotless_domain(domain)
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

fn matches_private_reverse_dns_range(domain: &str) -> bool {
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

fn matches_dotless_domain(domain: &str) -> bool {
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

#[derive(Clone, Debug)]
enum IpMatcher {
    Exact(IpAddr),
    Network(IpNet),
    Private,
}

impl IpMatcher {
    fn parse(value: &str) -> Result<Self, RouterError> {
        if let Some(name) = value.strip_prefix("geoip:") {
            return match name {
                "private" => Ok(Self::Private),
                _ => Err(RouterError::InvalidIpMatcher {
                    value: value.to_owned(),
                    reason: "unsupported geoip list".to_owned(),
                }),
            };
        }
        if value.contains('/') {
            return value.parse::<IpNet>().map(Self::Network).map_err(|source| {
                RouterError::InvalidIpMatcher {
                    value: value.to_owned(),
                    reason: source.to_string(),
                }
            });
        }

        value
            .parse::<IpAddr>()
            .map(Self::Exact)
            .map_err(|source| RouterError::InvalidIpMatcher {
                value: value.to_owned(),
                reason: source.to_string(),
            })
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Exact(exact) => *exact == ip,
            Self::Network(network) => network.contains(&ip),
            Self::Private => is_private_ip(ip),
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xrs_common::{Destination, DestinationHost, Network};
    use xrs_config::{
        InboundConfig, InboundProtocol, LogConfig, OutboundConfig, OutboundProtocol, RoutingConfig,
    };

    #[test]
    fn falls_back_to_first_outbound() {
        let config = config_with_rules(Vec::new());
        let router = Router::from_config(&config).unwrap();
        let session = domain_session("socks-in", "example.com", 443);

        assert_eq!(router.pick_outbound(&session), "direct");
    }

    #[test]
    fn exposes_rule_match_separately_from_default() {
        let config = config_with_rules(vec![rule(
            vec!["socks-in"],
            Some("443"),
            vec![],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_rule_outbound(&domain_session("socks-in", "example.com", 443)),
            Some("blocked")
        );
        assert_eq!(
            router.pick_rule_outbound(&domain_session("socks-in", "example.com", 80)),
            None
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
            "direct"
        );
    }

    #[test]
    fn parses_ip_if_non_match_domain_strategy() {
        let mut config = config_with_rules(Vec::new());
        config.routing.domain_strategy = Some("IPIfNonMatch".to_owned());
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.domain_strategy(),
            RoutingDomainStrategy::IpIfNonMatch
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let config = config_with_rules(vec![
            rule(vec!["socks-in"], Some("443"), vec![], vec![], "blocked"),
            rule(vec!["socks-in"], None, vec![], vec![], "direct"),
        ]);
        let router = Router::from_config(&config).unwrap();
        let session = domain_session("socks-in", "example.com", 443);

        assert_eq!(router.pick_outbound(&session), "blocked");
    }

    #[test]
    fn first_matching_rule_wins_across_candidate_sessions() {
        let config = config_with_rules(vec![
            rule(vec!["socks-in"], None, vec![], vec!["::1"], "blocked"),
            rule(vec!["socks-in"], None, vec![], vec!["127.0.0.1"], "direct"),
        ]);
        let router = Router::from_config(&config).unwrap();
        let sessions = vec![
            ip_session("socks-in", "127.0.0.1", 443),
            ip_session("socks-in", "::1", 443),
        ];

        assert_eq!(
            router.pick_rule_outbound_for_any(&sessions),
            Some("blocked")
        );
    }

    #[test]
    fn matches_port_range_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            Some("8000-8999,443"),
            vec![],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 8443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 9443)),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_port_range_rules_at_startup() {
        let config = config_with_rules(vec![rule(
            vec![],
            Some("9000-8000"),
            vec![],
            vec![],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidRoutingMatcher(ConfigError::InvalidRoutingPortMatcher { value, .. })) if value == "9000-8000"
        ));
    }

    #[test]
    fn matches_network_rules() {
        let mut tcp_rule = rule(vec![], None, vec![], vec![], "blocked");
        tcp_rule.network = Some("tcp".into());
        let mut udp_rule = rule(vec![], None, vec![], vec![], "blocked");
        udp_rule.network = Some("udp".into());

        let tcp_router = Router::from_config(&config_with_rules(vec![tcp_rule])).unwrap();
        let udp_router = Router::from_config(&config_with_rules(vec![udp_rule])).unwrap();

        assert_eq!(
            tcp_router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Tcp
            )),
            "blocked"
        );
        assert_eq!(
            tcp_router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Udp
            )),
            "direct"
        );
        assert_eq!(
            udp_router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Udp
            )),
            "blocked"
        );
    }

    #[test]
    fn matches_network_list_rules() {
        let mut network_rule = rule(vec![], None, vec![], vec![], "blocked");
        network_rule.network = Some("tcp,udp".into());
        let router = Router::from_config(&config_with_rules(vec![network_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Tcp
            )),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Udp
            )),
            "blocked"
        );
    }

    #[test]
    fn rejects_invalid_network_rules_at_startup() {
        let mut network_rule = rule(vec![], None, vec![], vec![], "blocked");
        network_rule.network = Some("tcp,quic".into());
        assert!(matches!(
            Router::from_config(&config_with_rules(vec![network_rule])),
            Err(RouterError::InvalidRoutingMatcher(ConfigError::InvalidRoutingNetworkMatcher { value, .. })) if value == "quic"
        ));
    }

    #[test]
    fn matches_domain_suffix_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["domain:example.com"],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "www.example.com", 80)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.net", 80)),
            "direct"
        );
    }

    #[test]
    fn matches_full_and_keyword_domain_rules() {
        let config = config_with_rules(vec![
            rule(
                vec![],
                None,
                vec!["full:login.example.com"],
                vec![],
                "blocked",
            ),
            rule(vec![], None, vec!["keyword:tracker"], vec![], "blocked"),
        ]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "login.example.com", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "cdn-tracker.example.net", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "api.example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn matches_regexp_domain_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec![r"regexp:^api-[0-9]+\.example\.com$"],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "api-123.example.com", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "www.example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_regexp_domain_rules_at_startup() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["regexp:["],
            vec![],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidDomainMatcher { value, .. }) if value == "regexp:["
        ));
    }

    #[test]
    fn matches_geosite_private_domain_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["geosite:private"],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        for host in [
            "router.local",
            "home.arpa",
            "printer",
            "router.asus.com",
            "setup.tplinkwifi.net",
            "16.172.in-addr.arpa",
            "64.100.in-addr.arpa",
            "8.e.f.ip6.arpa",
        ] {
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", host, 443)),
                "blocked",
                "{host} should match geosite:private"
            );
        }
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "15.172.in-addr.arpa", 443)),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "64.128.in-addr.arpa", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_unsupported_geosite_rules_at_startup() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["geosite:cn"],
            vec![],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidDomainMatcher { value, .. }) if value == "geosite:cn"
        ));
    }

    #[test]
    fn matches_source_ip_rules() {
        let mut source_rule = rule(vec![], None, vec![], vec![], "blocked");
        source_rule.source = vec!["127.0.0.1".to_owned(), "192.0.2.0/24".to_owned()];
        let router = Router::from_config(&config_with_rules(vec![source_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443)
                    .with_source_ip("127.0.0.1".parse().unwrap())
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443)
                    .with_source_ip("192.0.2.55".parse().unwrap())
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443)
                    .with_source_ip("198.51.100.1".parse().unwrap())
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_source_ip_rules_at_startup() {
        let mut source_rule = rule(vec![], None, vec![], vec![], "blocked");
        source_rule.source = vec!["not-ip".to_owned()];
        assert!(matches!(
            Router::from_config(&config_with_rules(vec![source_rule])),
            Err(RouterError::InvalidIpMatcher { value, .. }) if value == "not-ip"
        ));
    }

    #[test]
    fn matches_source_port_rules() {
        let mut source_port_rule = rule(vec![], None, vec![], vec![], "blocked");
        source_port_rule.source_port = Some("40000-49999,53000".into());
        let router = Router::from_config(&config_with_rules(vec![source_port_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_source_port(45000)
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_source_port(53000)
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_source_port(53001)
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_source_port_rules_at_startup() {
        let mut source_port_rule = rule(vec![], None, vec![], vec![], "blocked");
        source_port_rule.source_port = Some("9000-8000".into());
        assert!(matches!(
            Router::from_config(&config_with_rules(vec![source_port_rule])),
            Err(RouterError::InvalidRoutingMatcher(ConfigError::InvalidRoutingPortMatcher { value, .. })) if value == "9000-8000"
        ));
    }

    #[test]
    fn matches_geoip_private_ip_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec![],
            vec!["geoip:private"],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        for host in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "100.64.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert_eq!(
                router.pick_outbound(&ip_session("socks-in", host, 443)),
                "blocked",
                "{host} should match geoip:private"
            );
        }
        assert_eq!(
            router.pick_outbound(&ip_session("socks-in", "8.8.8.8", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_unsupported_geoip_rules_at_startup() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec![],
            vec!["geoip:cn"],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidIpMatcher { value, .. }) if value == "geoip:cn"
        ));
    }

    #[test]
    fn matches_ip_and_cidr_rules() {
        let config = config_with_rules(vec![
            rule(vec![], None, vec![], vec!["10.0.0.0/8"], "blocked"),
            rule(vec![], None, vec![], vec!["192.0.2.7"], "blocked"),
        ]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&ip_session("socks-in", "10.1.2.3", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&ip_session("socks-in", "192.0.2.7", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&ip_session("socks-in", "198.51.100.1", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_ip_matchers_at_startup() {
        let config = config_with_rules(vec![rule(vec![], None, vec![], vec!["not-ip"], "blocked")]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidIpMatcher { value, .. }) if value == "not-ip"
        ));
    }

    fn config_with_rules(rules: Vec<RoutingRuleConfig>) -> RootConfig {
        RootConfig {
            log: LogConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_owned(),
                listen: None,
                port: 1080,
                protocol: InboundProtocol::Socks,
                settings: None,
                stream_settings: None,
                sniffing: None,
                allocate: None,
            }],
            outbounds: vec![
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
            routing: RoutingConfig {
                rules,
                balancers: Vec::new(),
                domain_strategy: None,
                domain_matcher: None,
            },
            ..RootConfig::default()
        }
    }

    fn rule(
        inbound_tag: Vec<&str>,
        port: Option<&str>,
        domain: Vec<&str>,
        ip: Vec<&str>,
        outbound_tag: &str,
    ) -> RoutingRuleConfig {
        RoutingRuleConfig {
            rule_type: None,
            inbound_tag: inbound_tag.into_iter().map(str::to_owned).collect(),
            port: port.map(Into::into),
            domain: domain.into_iter().map(str::to_owned).collect(),
            ip: ip.into_iter().map(str::to_owned).collect(),
            source: Vec::new(),
            source_port: None,
            network: None,
            protocol: Vec::new(),
            user: Vec::new(),
            outbound_tag: Some(outbound_tag.to_owned()),
            balancer_tag: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    fn domain_session(inbound_tag: &str, host: &str, port: u16) -> SessionContext {
        SessionContext::new(
            inbound_tag,
            Destination::tcp(DestinationHost::parse(host).unwrap(), port),
        )
    }

    fn ip_session(inbound_tag: &str, host: &str, port: u16) -> SessionContext {
        SessionContext::new(
            inbound_tag,
            Destination::tcp(DestinationHost::parse(host).unwrap(), port),
        )
    }

    fn network_session(
        inbound_tag: &str,
        host: &str,
        port: u16,
        network: Network,
    ) -> SessionContext {
        SessionContext::new(
            inbound_tag,
            Destination {
                host: DestinationHost::parse(host).unwrap(),
                port,
                network,
            },
        )
    }
}
