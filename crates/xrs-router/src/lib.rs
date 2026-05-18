#![forbid(unsafe_code)]

use ipnet::IpNet;
use regex::Regex;
use std::{collections::HashMap, net::IpAddr};
use thiserror::Error;
use xrs_common::{DestinationHost, Network, SessionContext};
use xrs_config::{
    ConfigError, RootConfig, RoutingBalancerConfig, RoutingNetwork, RoutingPortRange,
    RoutingRuleConfig,
};

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
    IpOnDemand,
    UseIpv4,
    UseIpv6,
    UseIpv4v6,
    UseIpv6v4,
}

#[derive(Clone, Debug)]
pub struct Router {
    default_outbound: String,
    domain_strategy: RoutingDomainStrategy,
    rules: Vec<RouteRule>,
    balancers: HashMap<String, Balancer>,
}

#[derive(Clone, Debug)]
struct Balancer {
    targets: Vec<String>,
    fallback_tag: Option<String>,
    strategy: BalancerStrategy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BalancerStrategy {
    First,
    Random,
}

impl Balancer {
    fn from_config(
        config: &RoutingBalancerConfig,
        outbound_tags: &[String],
    ) -> Option<(String, Self)> {
        let mut targets = outbound_tags
            .iter()
            .filter(|tag| {
                config
                    .selector
                    .iter()
                    .any(|selector| tag.starts_with(selector))
            })
            .cloned()
            .collect::<Vec<_>>();
        targets.sort();
        let fallback_tag = config.fallback_tag.clone();
        if targets.is_empty() && fallback_tag.is_none() {
            return None;
        }
        let strategy = match config
            .strategy
            .as_ref()
            .and_then(|strategy| strategy.strategy_type.as_deref())
        {
            Some("random") => BalancerStrategy::Random,
            _ => BalancerStrategy::First,
        };
        Some((
            config.tag.clone(),
            Self {
                targets,
                fallback_tag,
                strategy,
            },
        ))
    }

    fn pick_target(&self) -> Option<&str> {
        match self.strategy {
            BalancerStrategy::First => self.targets.first().map(String::as_str),
            BalancerStrategy::Random => {
                if self.targets.is_empty() {
                    None
                } else {
                    self.targets
                        .get(fastrand::usize(..self.targets.len()))
                        .map(String::as_str)
                }
            }
        }
        .or(self.fallback_tag.as_deref())
    }
}

impl Router {
    pub fn from_config(config: &RootConfig) -> Result<Self, RouterError> {
        let default_outbound = config
            .outbounds
            .first()
            .map(|outbound| outbound.tag.clone())
            .ok_or(RouterError::MissingDefaultOutbound)?;
        let outbound_tags = config
            .outbounds
            .iter()
            .map(|outbound| outbound.tag.clone())
            .collect::<Vec<_>>();
        let balancers = config
            .routing
            .balancers
            .iter()
            .filter_map(|balancer| Balancer::from_config(balancer, &outbound_tags))
            .collect::<HashMap<_, _>>();
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
            balancers,
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
            .map(|rule| self.resolve_rule_target(rule))
    }

    #[must_use]
    pub fn pick_rule_outbound_for_any<'a>(
        &'a self,
        sessions: &[SessionContext],
    ) -> Option<&'a str> {
        self.rules
            .iter()
            .find(|rule| sessions.iter().any(|session| rule.matches(session)))
            .map(|rule| self.resolve_rule_target(rule))
    }

    #[must_use]
    pub fn pick_ip_rule_outbound_for_any<'a>(
        &'a self,
        sessions: &[SessionContext],
    ) -> Option<&'a str> {
        self.rules
            .iter()
            .find(|rule| {
                rule.has_destination_ip_matcher()
                    && sessions.iter().any(|session| rule.matches(session))
            })
            .map(|rule| self.resolve_rule_target(rule))
    }

    fn resolve_rule_target<'a>(&'a self, rule: &'a RouteRule) -> &'a str {
        match &rule.target {
            RouteTarget::Outbound(tag) => tag.as_str(),
            RouteTarget::Balancer(tag) => self
                .balancers
                .get(tag)
                .and_then(Balancer::pick_target)
                .unwrap_or(self.default_outbound.as_str()),
        }
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
            Some("IPIfNonMatch" | "UseIP") => Self::IpIfNonMatch,
            Some("IPOnDemand") => Self::IpOnDemand,
            Some("UseIPv4") => Self::UseIpv4,
            Some("UseIPv6") => Self::UseIpv6,
            Some("UseIPv4v6") => Self::UseIpv4v6,
            Some("UseIPv6v4") => Self::UseIpv6v4,
            _ => Self::AsIs,
        }
    }
}

#[derive(Clone, Debug)]
struct RouteRule {
    inbound_tag: Vec<String>,
    port: Vec<RoutingPortRange>,
    network: Vec<RoutingNetwork>,
    domain: Vec<DomainMatcher>,
    ip: Vec<IpMatcher>,
    source: Vec<IpMatcher>,
    source_port: Vec<RoutingPortRange>,
    user: Vec<String>,
    protocol: Vec<String>,
    attrs: Option<AttrsMatcher>,
    target: RouteTarget,
}

#[derive(Clone, Debug)]
enum RouteTarget {
    Outbound(String),
    Balancer(String),
}

#[derive(Clone, Debug)]
enum AttrsMatcher {
    HttpMethod(String),
    HttpMethodNot(String),
    HttpPath(String),
    HttpPathNot(String),
    HttpPathPrefix(String),
    HttpPathContains(String),
    All(Vec<AttrsMatcher>),
    Any(Vec<AttrsMatcher>),
}

impl AttrsMatcher {
    fn parse(value: &serde_json::Value) -> Result<Option<Self>, RouterError> {
        match value {
            serde_json::Value::String(value) if value.is_empty() => Ok(None),
            serde_json::Value::String(value) => {
                parse_attrs_matcher(value).map(Some).ok_or_else(|| {
                    RouterError::InvalidRoutingMatcher(ConfigError::UnsupportedRoutingRuleField(
                        "attrs".to_owned(),
                    ))
                })
            }
            value if is_inert_attrs_value(value) => Ok(None),
            _ => Err(RouterError::InvalidRoutingMatcher(
                ConfigError::UnsupportedRoutingRuleField("attrs".to_owned()),
            )),
        }
    }

    fn matches(&self, session: &SessionContext) -> bool {
        match self {
            Self::HttpMethod(expected) => session
                .attributes
                .get(":method")
                .is_some_and(|method| method == expected),
            Self::HttpMethodNot(expected) => session
                .attributes
                .get(":method")
                .is_some_and(|method| method != expected),
            Self::HttpPath(expected) => session
                .attributes
                .get(":path")
                .is_some_and(|path| path == expected),
            Self::HttpPathNot(expected) => session
                .attributes
                .get(":path")
                .is_some_and(|path| path != expected),
            Self::HttpPathPrefix(expected) => session
                .attributes
                .get(":path")
                .is_some_and(|path| path.starts_with(expected)),
            Self::HttpPathContains(expected) => session
                .attributes
                .get(":path")
                .is_some_and(|path| path.contains(expected)),
            Self::All(matchers) => matchers.iter().all(|matcher| matcher.matches(session)),
            Self::Any(matchers) => matchers.iter().any(|matcher| matcher.matches(session)),
        }
    }
}

fn parse_attrs_matcher(value: &str) -> Option<AttrsMatcher> {
    parse_attrs_or_matcher(value).or_else(|| parse_attrs_non_or_matcher(value))
}

fn parse_attrs_or_matcher(value: &str) -> Option<AttrsMatcher> {
    let mut operands = value.split(" || ");
    let mut matchers = vec![
        parse_attrs_non_or_matcher(operands.next()?)?,
        parse_attrs_non_or_matcher(operands.next()?)?,
    ];
    matchers.extend(
        operands
            .map(parse_attrs_non_or_matcher)
            .collect::<Option<Vec<_>>>()?,
    );
    Some(AttrsMatcher::Any(matchers))
}

fn parse_attrs_non_or_matcher(value: &str) -> Option<AttrsMatcher> {
    let value = strip_attrs_parentheses(value).unwrap_or(value);

    parse_attrs_single_matcher(value).or_else(|| parse_attrs_compound_matcher(value))
}

fn strip_attrs_parentheses(value: &str) -> Option<&str> {
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

fn parse_attrs_compound_matcher(value: &str) -> Option<AttrsMatcher> {
    let operands = value.split(" && ").collect::<Vec<_>>();
    if operands.len() < 2 {
        return None;
    }

    let mut has_method = false;
    let mut has_path = false;
    let matchers = operands
        .into_iter()
        .map(|operand| {
            parse_attrs_method_like(operand)
                .inspect(|_| has_method = true)
                .or_else(|| parse_attrs_path_like(operand).inspect(|_| has_path = true))
        })
        .collect::<Option<Vec<_>>>()?;

    (has_method && has_path).then_some(AttrsMatcher::All(matchers))
}

fn parse_attrs_method_like(value: &str) -> Option<AttrsMatcher> {
    let value = strip_attrs_parentheses(value).unwrap_or(value);

    parse_attrs_method_matcher(value)
        .map(|method| AttrsMatcher::HttpMethod(method.to_owned()))
        .or_else(|| {
            parse_attrs_method_not_matcher(value)
                .map(|method| AttrsMatcher::HttpMethodNot(method.to_owned()))
        })
}

fn parse_attrs_path_like(value: &str) -> Option<AttrsMatcher> {
    let value = strip_attrs_parentheses(value).unwrap_or(value);

    parse_attrs_path_matcher(value)
        .map(|path| AttrsMatcher::HttpPath(path.to_owned()))
        .or_else(|| {
            parse_attrs_path_not_matcher(value)
                .map(|path| AttrsMatcher::HttpPathNot(path.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_prefix_matcher(value)
                .map(|path| AttrsMatcher::HttpPathPrefix(path.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_contains_matcher(value)
                .map(|path| AttrsMatcher::HttpPathContains(path.to_owned()))
        })
}

fn parse_attrs_single_matcher(value: &str) -> Option<AttrsMatcher> {
    parse_attrs_method_matcher(value)
        .map(|method| AttrsMatcher::HttpMethod(method.to_owned()))
        .or_else(|| {
            parse_attrs_method_not_matcher(value)
                .map(|method| AttrsMatcher::HttpMethodNot(method.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_matcher(value).map(|path| AttrsMatcher::HttpPath(path.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_not_matcher(value)
                .map(|path| AttrsMatcher::HttpPathNot(path.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_prefix_matcher(value)
                .map(|path| AttrsMatcher::HttpPathPrefix(path.to_owned()))
        })
        .or_else(|| {
            parse_attrs_path_contains_matcher(value)
                .map(|path| AttrsMatcher::HttpPathContains(path.to_owned()))
        })
}

fn parse_attrs_method_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":method", "==", "'")
        .filter(|method| !method.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":method", "==", "\"")
                .filter(|method| !method.contains('"'))
        })
        .filter(|method| http_method_token(method))
}

fn parse_attrs_method_not_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":method", "!=", "'")
        .filter(|method| !method.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":method", "!=", "\"")
                .filter(|method| !method.contains('"'))
        })
        .filter(|method| http_method_token(method))
}

fn parse_attrs_path_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":path", "==", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":path", "==", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_attrs_path_not_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_value(value, ":path", "!=", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_value(value, ":path", "!=", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_attrs_path_prefix_matcher(value: &str) -> Option<&str> {
    parse_quoted_attrs_call_value(value, ":path", "startswith", "'")
        .filter(|path| !path.is_empty() && !path.contains('\''))
        .or_else(|| {
            parse_quoted_attrs_call_value(value, ":path", "startswith", "\"")
                .filter(|path| !path.is_empty() && !path.contains('"'))
        })
}

fn parse_attrs_path_contains_matcher(value: &str) -> Option<&str> {
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

fn is_inert_attrs_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(value) => value.is_empty(),
        serde_json::Value::Array(value) => value.is_empty(),
        serde_json::Value::Object(value) => value.is_empty(),
        _ => false,
    }
}

fn routing_network_matches(matcher: RoutingNetwork, runtime: Network) -> bool {
    matches!(
        (matcher, runtime),
        (RoutingNetwork::Tcp, Network::Tcp) | (RoutingNetwork::Udp, Network::Udp)
    )
}

impl RouteRule {
    fn has_destination_ip_matcher(&self) -> bool {
        !self.ip.is_empty()
    }

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
        let network_matches = self.network.is_empty()
            || self
                .network
                .iter()
                .any(|network| routing_network_matches(*network, session.destination.network));
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
        let user_matches = self.user.is_empty()
            || session
                .user
                .as_ref()
                .is_some_and(|user| self.user.iter().any(|candidate| candidate == user));
        let protocol_matches = self.protocol.is_empty()
            || session.protocol.as_ref().is_some_and(|protocol| {
                self.protocol.iter().any(|candidate| candidate == protocol)
            });
        let attrs_matches = self
            .attrs
            .as_ref()
            .is_none_or(|attrs| attrs.matches(session));

        inbound_matches
            && port_matches
            && network_matches
            && domain_matches
            && ip_matches
            && source_matches
            && source_port_matches
            && user_matches
            && protocol_matches
            && attrs_matches
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
        let attrs = value
            .attrs
            .as_ref()
            .map_or_else(|| Ok(None), AttrsMatcher::parse)?;

        Ok(Self {
            inbound_tag: value.inbound_tag.clone(),
            port,
            network,
            domain,
            ip,
            source,
            source_port,
            user: value.user.clone(),
            protocol: value
                .protocol
                .iter()
                .filter(|protocol| !protocol.is_empty())
                .cloned()
                .collect(),
            attrs,
            target: match (&value.outbound_tag, &value.balancer_tag) {
                (Some(tag), None) => RouteTarget::Outbound(tag.clone()),
                (None, Some(tag)) => RouteTarget::Balancer(tag.clone()),
                _ => {
                    return Err(RouterError::InvalidRoutingMatcher(
                        ConfigError::UnsupportedRoutingRuleField("outboundTag".to_owned()),
                    ));
                }
            },
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
    GeositeCn,
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
                "cn" => Ok(Self::GeositeCn),
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
            Self::GeositeCn => is_cn_geosite_domain(&domain),
        }
    }
}

fn is_cn_geosite_domain(domain: &str) -> bool {
    const SUFFIX: &[&str] = &["baidu.com", "qq.com", "taobao.com"];
    SUFFIX
        .iter()
        .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
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
        "c.f.ip6.arpa",
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
    Cn,
}

impl IpMatcher {
    fn parse(value: &str) -> Result<Self, RouterError> {
        if let Some(name) = value.strip_prefix("geoip:") {
            return match name {
                "private" => Ok(Self::Private),
                "cn" => Ok(Self::Cn),
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
            Self::Cn => is_cn_ip(ip),
        }
    }
}

fn is_cn_ip(ip: IpAddr) -> bool {
    const CN_V4_CIDRS: &[&str] = &["1.0.1.0/24", "1.0.2.0/23"];
    CN_V4_CIDRS.iter().any(|cidr| {
        cidr.parse::<IpNet>()
            .is_ok_and(|network| network.contains(&ip))
    })
}

fn is_private_ip(ip: IpAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use xrs_common::{Destination, DestinationHost, Network};
    use xrs_config::{
        InboundConfig, InboundProtocol, LogConfig, OutboundConfig, OutboundProtocol,
        RoutingBalancerConfig, RoutingBalancerStrategyConfig, RoutingConfig,
    };

    #[test]
    fn falls_back_to_first_outbound() {
        let config = config_with_rules(Vec::new());
        let router = Router::from_config(&config).unwrap();
        let session = domain_session("socks-in", "example.com", 443);

        assert_eq!(router.pick_outbound(&session), "direct");
    }

    #[test]
    fn resolves_balancer_rule_to_first_selector() {
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer("auto", vec!["block", "direct"], None)],
        ))
        .unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
    }

    #[test]
    fn random_balancer_strategy_uses_multiple_selector_targets() {
        let mut balancer = balancer("auto", vec!["blocked", "direct"], None);
        balancer.strategy = Some(RoutingBalancerStrategyConfig {
            strategy_type: Some("random".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer],
        ))
        .unwrap();

        let mut selected = std::collections::BTreeSet::new();
        for _ in 0..64 {
            selected.insert(router.pick_outbound(&domain_session("socks-in", "example.com", 443)));
        }

        assert_eq!(
            selected,
            std::collections::BTreeSet::from(["blocked", "direct"])
        );
    }

    #[test]
    fn least_ping_balancer_strategy_uses_first_selector_until_metrics_exist() {
        let mut balancer = balancer("auto", vec!["blocked", "direct"], None);
        balancer.strategy = Some(RoutingBalancerStrategyConfig {
            strategy_type: Some("leastPing".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer],
        ))
        .unwrap();

        for _ in 0..16 {
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
                "blocked"
            );
        }
    }

    #[test]
    fn resolves_balancer_rule_to_fallback_when_selector_is_empty() {
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer("auto", Vec::new(), Some("blocked"))],
        ))
        .unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
    }

    #[test]
    fn resolves_balancer_selectors_by_outbound_tag_prefix() {
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer("auto", vec!["block"], Some("direct"))],
        ))
        .unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
    }

    #[test]
    fn resolves_balancer_to_fallback_when_selectors_match_no_outbounds() {
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer("auto", vec!["missing"], Some("blocked"))],
        ))
        .unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
    }

    #[test]
    fn random_balancer_falls_back_when_selectors_match_no_outbounds() {
        let mut balancer = balancer("auto", vec!["missing"], Some("blocked"));
        balancer.strategy = Some(RoutingBalancerStrategyConfig {
            strategy_type: Some("random".to_owned()),
            extra: std::collections::BTreeMap::new(),
        });
        let router = Router::from_config(&config_with_rules_and_balancers(
            vec![balancer_rule(
                vec![],
                None,
                vec!["example.com"],
                vec![],
                Some("auto"),
            )],
            vec![balancer],
        ))
        .unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
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
        for domain_strategy in ["IPIfNonMatch", "UseIP"] {
            let mut config = config_with_rules(Vec::new());
            config.routing.domain_strategy = Some(domain_strategy.to_owned());
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.domain_strategy(),
                RoutingDomainStrategy::IpIfNonMatch
            );
        }
    }

    #[test]
    fn parses_ip_on_demand_domain_strategy() {
        let mut config = config_with_rules(Vec::new());
        config.routing.domain_strategy = Some("IPOnDemand".to_owned());
        let router = Router::from_config(&config).unwrap();

        assert_eq!(router.domain_strategy(), RoutingDomainStrategy::IpOnDemand);
    }

    #[test]
    fn parses_use_ipv6_domain_strategy() {
        let mut config = config_with_rules(Vec::new());
        config.routing.domain_strategy = Some("UseIPv6".to_owned());
        let router = Router::from_config(&config).unwrap();

        assert_eq!(router.domain_strategy(), RoutingDomainStrategy::UseIpv6);
    }

    #[test]
    fn parses_dual_family_domain_strategies() {
        for (domain_strategy, expected) in [
            ("UseIPv4v6", RoutingDomainStrategy::UseIpv4v6),
            ("UseIPv6v4", RoutingDomainStrategy::UseIpv6v4),
        ] {
            let mut config = config_with_rules(Vec::new());
            config.routing.domain_strategy = Some(domain_strategy.to_owned());
            let router = Router::from_config(&config).unwrap();

            assert_eq!(router.domain_strategy(), expected);
        }
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
        network_rule.network = Some("tcp,,udp,".into());
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
    fn accepts_quic_network_rules_without_matching_tcp_or_udp_sessions() {
        let mut quic_rule = rule(vec![], None, vec![], vec![], "blocked");
        quic_rule.network = Some("quic".into());
        let router = Router::from_config(&config_with_rules(vec![quic_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Tcp
            )),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&network_session(
                "socks-in",
                "example.com",
                443,
                Network::Udp
            )),
            "direct"
        );
    }

    #[test]
    fn rejects_invalid_network_rules_at_startup() {
        let mut network_rule = rule(vec![], None, vec![], vec![], "blocked");
        network_rule.network = Some("tcp,grpc".into());
        assert!(matches!(
            Router::from_config(&config_with_rules(vec![network_rule])),
            Err(RouterError::InvalidRoutingMatcher(ConfigError::InvalidRoutingNetworkMatcher { value, .. })) if value == "grpc"
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
    fn matches_http_protocol_rules() {
        let mut protocol_rule = rule(vec![], None, vec![], vec![], "blocked");
        protocol_rule.protocol = vec!["http".to_owned()];
        let config = config_with_rules(vec![protocol_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_protocol("http")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn matches_tls_protocol_rules() {
        let mut protocol_rule = rule(vec![], None, vec![], vec![], "blocked");
        protocol_rule.protocol = vec!["tls".to_owned()];
        let config = config_with_rules(vec![protocol_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_protocol("tls")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_protocol("http")
            ),
            "direct"
        );
    }

    #[test]
    fn matches_quic_protocol_rules() {
        let mut protocol_rule = rule(vec![], None, vec![], vec![], "blocked");
        protocol_rule.protocol = vec!["quic".to_owned()];
        let config = config_with_rules(vec![protocol_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_protocol("quic")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_protocol("tls")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn ignores_empty_protocol_rule_matchers() {
        let mut protocol_rule = rule(vec![], None, vec![], vec![], "blocked");
        protocol_rule.protocol = vec!["".to_owned()];
        let config = config_with_rules(vec![protocol_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "blocked"
        );
    }

    #[test]
    fn matches_http_method_attrs_rules() {
        for method in ["GET", "POST"] {
            for attrs in [
                format!("attrs[':method'] == '{method}'"),
                format!("attrs[':method'] == \"{method}\""),
                format!("attrs[\":method\"] == '{method}'"),
                format!("attrs[\":method\"] == \"{method}\""),
            ] {
                let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
                attrs_rule.attrs = Some(serde_json::Value::String(attrs));
                let config = config_with_rules(vec![attrs_rule]);
                let router = Router::from_config(&config).unwrap();

                assert_eq!(
                    router.pick_outbound(
                        &domain_session("socks-in", "example.com", 80)
                            .with_attribute(":method", method)
                    ),
                    "blocked"
                );
                assert_eq!(
                    router.pick_outbound(
                        &domain_session("socks-in", "example.com", 80)
                            .with_attribute(":method", "PATCH")
                    ),
                    "direct"
                );
                assert_eq!(
                    router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                    "direct"
                );
            }
        }
    }

    #[test]
    fn matches_http_method_inequality_attrs_rules() {
        for attrs in [
            "attrs[':method'] != 'GET'",
            "attrs[':method'] != \"GET\"",
            "attrs[\":method\"] != 'GET'",
            "attrs[\":method\"] != \"GET\"",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80).with_attribute(":method", "GET")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                "direct"
            );
        }
    }

    #[test]
    fn matches_compound_http_method_inequality_attrs_rules() {
        for attrs in [
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
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/blocked")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/blocked")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/allowed")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/blocked")
                ),
                "direct"
            );
        }
    }

    #[test]
    fn matches_http_path_attrs_rules() {
        for path in ["/", "/blocked"] {
            for attrs in [
                format!("attrs[':path'] == '{path}'"),
                format!("attrs[':path'] == \"{path}\""),
                format!("attrs[\":path\"] == '{path}'"),
                format!("attrs[\":path\"] == \"{path}\""),
            ] {
                let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
                attrs_rule.attrs = Some(serde_json::Value::String(attrs));
                let config = config_with_rules(vec![attrs_rule]);
                let router = Router::from_config(&config).unwrap();

                assert_eq!(
                    router.pick_outbound(
                        &domain_session("socks-in", "example.com", 80)
                            .with_attribute(":path", path)
                    ),
                    "blocked"
                );
                assert_eq!(
                    router.pick_outbound(
                        &domain_session("socks-in", "example.com", 80)
                            .with_attribute(":path", "/allowed")
                    ),
                    "direct"
                );
                assert_eq!(
                    router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                    "direct"
                );
            }
        }
    }

    #[test]
    fn matches_http_path_inequality_attrs_rules() {
        for attrs in [
            "attrs[':path'] != '/blocked'",
            "attrs[':path'] != \"/blocked\"",
            "attrs[\":path\"] != '/blocked'",
            "attrs[\":path\"] != \"/blocked\"",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/allowed")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/blocked")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                "direct"
            );
        }
    }

    #[test]
    fn matches_http_path_prefix_attrs_rules() {
        for attrs in [
            "attrs[':path'].startswith('/blocked')",
            "attrs[':path'].startswith(\"/blocked\")",
            "attrs[\":path\"].startswith('/blocked')",
            "attrs[\":path\"].startswith(\"/blocked\")",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/blocked/page")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/allowed")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                "direct"
            );
        }
    }

    #[test]
    fn matches_http_path_contains_attrs_rules() {
        for attrs in [
            "attrs[':path'].contains('/ads')",
            "attrs[':path'].contains(\"/ads\")",
            "attrs[\":path\"].contains('/ads')",
            "attrs[\":path\"].contains(\"/ads\")",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/static/ads/banner.js")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":path", "/static/app.js")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                "direct"
            );
        }
    }

    #[test]
    fn matches_compound_http_attrs_rules() {
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
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/blocked")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/blocked")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/allowed")
                ),
                "direct"
            );
        }
    }

    #[test]
    fn matches_chained_compound_http_attrs_rules() {
        for attrs in [
            "attrs[':method'] == 'GET' && attrs[':path'].startswith('/api') && attrs[':path'].contains('/v1')",
            "attrs[':path'].startswith('/api') && attrs[':method'] == 'GET' && attrs[':path'].contains('/v1')",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/api/users/v1")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/api/users/v1")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/api/users/v2")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80).with_attribute(":method", "GET")
                ),
                "direct"
            );
        }
    }

    #[test]
    fn matches_compound_http_path_inequality_attrs_rules() {
        for attrs in [
            "attrs[':method'] == 'GET' && attrs[':path'] != '/blocked'",
            "attrs[':path'] != '/blocked' && attrs[':method'] == 'GET'",
            "attrs[':method'] == \"GET\" && attrs[':path'] != \"/blocked\"",
            "attrs[':path'] != \"/blocked\" && attrs[':method'] == \"GET\"",
            "attrs[\":method\"] == \"GET\" && attrs[\":path\"] != \"/blocked\"",
            "attrs[\":path\"] != \"/blocked\" && attrs[\":method\"] == \"GET\"",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/allowed")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/blocked")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/allowed")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80).with_attribute(":method", "GET")
                ),
                "direct"
            );
        }
    }

    #[test]
    fn matches_parenthesized_compound_http_attrs_rules() {
        let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
        attrs_rule.attrs = Some(serde_json::Value::String(
            "(attrs[':method'] == 'POST') && (attrs[':path'].startswith('/api/'))".to_owned(),
        ));
        let config = config_with_rules(vec![attrs_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80)
                    .with_attribute(":method", "POST")
                    .with_attribute(":path", "/api/users")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80)
                    .with_attribute(":method", "GET")
                    .with_attribute(":path", "/api/users")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80)
                    .with_attribute(":method", "POST")
                    .with_attribute(":path", "/web")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":method", "POST")
            ),
            "direct"
        );
    }

    #[test]
    fn matches_or_http_attrs_rules() {
        for attrs in [
            "attrs[':method'] == 'GET' || attrs[':method'] == 'POST'",
            "attrs[':method'] == \"GET\" || attrs[':method'] == \"POST\"",
            "attrs[\":method\"] == \"GET\" || attrs[\":method\"] == \"POST\"",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80).with_attribute(":method", "GET")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "PATCH")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
                "direct"
            );
        }
    }

    #[test]
    fn matches_chained_or_http_attrs_rules() {
        let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
        attrs_rule.attrs = Some(serde_json::Value::String(
            "attrs[':method'] == 'GET' || attrs[':method'] == 'POST' || attrs[':method'] == 'PUT'"
                .to_owned(),
        ));
        let config = config_with_rules(vec![attrs_rule]);
        let router = Router::from_config(&config).unwrap();

        for method in ["GET", "POST", "PUT"] {
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", method)
                ),
                "blocked"
            );
        }
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":method", "PATCH")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
            "direct"
        );
    }

    #[test]
    fn matches_parenthesized_or_http_attrs_rules() {
        let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
        attrs_rule.attrs = Some(serde_json::Value::String(
            "(attrs[':method'] == 'GET') || (attrs[':method'] == 'POST')".to_owned(),
        ));
        let config = config_with_rules(vec![attrs_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":method", "GET")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":method", "POST")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":method", "PATCH")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
            "direct"
        );
    }

    #[test]
    fn matches_or_http_method_path_attrs_rules() {
        for attrs in [
            "attrs[':method'] == 'GET' || attrs[':path'] == '/blocked'",
            "attrs[':path'] == '/blocked' || attrs[':method'] == 'GET'",
            "attrs[\":method\"] == \"GET\" || attrs[\":path\"] == \"/blocked\"",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));
            let config = config_with_rules(vec![attrs_rule]);
            let router = Router::from_config(&config).unwrap();

            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "GET")
                        .with_attribute(":path", "/allowed")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/blocked")
                ),
                "blocked"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/ads/banner")
                ),
                "direct"
            );
            assert_eq!(
                router.pick_outbound(
                    &domain_session("socks-in", "example.com", 80)
                        .with_attribute(":method", "POST")
                        .with_attribute(":path", "/allowed")
                ),
                "direct"
            );
        }
    }

    #[test]
    fn matches_or_http_path_attrs_rules() {
        let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
        attrs_rule.attrs = Some(serde_json::Value::String(
            "attrs[':path'] == '/blocked' || attrs[':path'].startswith('/ads')".to_owned(),
        ));
        let config = config_with_rules(vec![attrs_rule]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":path", "/blocked")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80)
                    .with_attribute(":path", "/ads/banner")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 80).with_attribute(":path", "/allowed")
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 80)),
            "direct"
        );
    }

    #[test]
    fn rejects_unsupported_attrs_rules_at_startup() {
        for attrs in [
            "attrs[':path'].startswith('')",
            "attrs[':path'].startswith('/blocked'",
            "attrs[':path'].startsWith('/blocked')",
            "attrs[':path'].startswith('/blocked'))",
            "attrs[':method'] == 'GE'T'",
            "attrs[':method'] != 'GE'T'",
            r#"attrs[":method"] == "GE"T""#,
            r#"attrs[":method"] != "GE"T""#,
            "attrs[':path'] == 'blo'cked'",
            "attrs[':path'] != 'blo'cked'",
            r#"attrs[":path"] == "blo"cked""#,
            r#"attrs[":path"] != "blo"cked""#,
            "attrs[':method'] == 'GET' && attrs[':method'] == 'POST'",
            "attrs[':path'] == '/blocked' && attrs[':path'] == '/other'",
        ] {
            let mut attrs_rule = rule(vec![], None, vec![], vec![], "blocked");
            attrs_rule.attrs = Some(serde_json::Value::String(attrs.to_owned()));

            assert!(matches!(
                Router::from_config(&config_with_rules(vec![attrs_rule])),
                Err(RouterError::InvalidRoutingMatcher(ConfigError::UnsupportedRoutingRuleField(field))) if field == "attrs"
            ));
        }
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
            "c.f.ip6.arpa",
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
    fn matches_geosite_cn_domain_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["geosite:cn"],
            vec![],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "baidu.com", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "www.baidu.com", 443)),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
    }

    #[test]
    fn rejects_unsupported_geosite_rules_at_startup() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec!["geosite:us"],
            vec![],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidDomainMatcher { value, .. }) if value == "geosite:us"
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
    fn matches_source_geoip_private_rules() {
        let mut source_rule = rule(vec![], None, vec![], vec![], "blocked");
        source_rule.source = vec!["geoip:private".to_owned()];
        let router = Router::from_config(&config_with_rules(vec![source_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443)
                    .with_source_ip("10.1.2.3".parse().unwrap())
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443)
                    .with_source_ip("8.8.8.8".parse().unwrap())
            ),
            "direct"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443)),
            "direct"
        );
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
    fn matches_user_rules() {
        let mut user_rule = rule(vec![], None, vec![], vec![], "blocked");
        user_rule.user = vec!["alice@example.com".to_owned(), "bob".to_owned()];
        let router = Router::from_config(&config_with_rules(vec![user_rule])).unwrap();

        assert_eq!(
            router.pick_outbound(
                &domain_session("socks-in", "example.com", 443).with_user("alice@example.com")
            ),
            "blocked"
        );
        assert_eq!(
            router.pick_outbound(&domain_session("socks-in", "example.com", 443).with_user("bob")),
            "blocked"
        );
        assert_eq!(
            router
                .pick_outbound(&domain_session("socks-in", "example.com", 443).with_user("carol")),
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
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
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
    fn matches_geoip_cn_ip_rules() {
        let config = config_with_rules(vec![rule(
            vec![],
            None,
            vec![],
            vec!["geoip:cn"],
            "blocked",
        )]);
        let router = Router::from_config(&config).unwrap();

        assert_eq!(
            router.pick_outbound(&ip_session("socks-in", "1.0.1.1", 443)),
            "blocked"
        );
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
            vec!["geoip:us"],
            "blocked",
        )]);
        assert!(matches!(
            Router::from_config(&config),
            Err(RouterError::InvalidIpMatcher { value, .. }) if value == "geoip:us"
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
        config_with_rules_and_balancers(rules, Vec::new())
    }

    fn config_with_rules_and_balancers(
        rules: Vec<RoutingRuleConfig>,
        balancers: Vec<RoutingBalancerConfig>,
    ) -> RootConfig {
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
                extra: Default::default(),
            }],
            outbounds: vec![
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
            routing: RoutingConfig {
                rules,
                balancers,
                domain_strategy: None,
                domain_matcher: None,
                extra: Default::default(),
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
        let mut rule = balancer_rule(inbound_tag, port, domain, ip, None);
        rule.outbound_tag = Some(outbound_tag.to_owned());
        rule
    }

    fn balancer_rule(
        inbound_tag: Vec<&str>,
        port: Option<&str>,
        domain: Vec<&str>,
        ip: Vec<&str>,
        balancer_tag: Option<&str>,
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
            attrs: None,
            outbound_tag: None,
            balancer_tag: balancer_tag.map(str::to_owned),
            extra: std::collections::BTreeMap::new(),
        }
    }

    fn balancer(
        tag: &str,
        selector: Vec<&str>,
        fallback_tag: Option<&str>,
    ) -> RoutingBalancerConfig {
        RoutingBalancerConfig {
            tag: tag.to_owned(),
            selector: selector.into_iter().map(str::to_owned).collect(),
            fallback_tag: fallback_tag.map(str::to_owned),
            strategy: None,
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
