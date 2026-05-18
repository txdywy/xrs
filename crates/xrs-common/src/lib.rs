#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, net::IpAddr, str::FromStr};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("domain name cannot be empty")]
    EmptyDomain,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DestinationHost {
    Ip(IpAddr),
    Domain(String),
}

impl DestinationHost {
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        if let Ok(ip) = IpAddr::from_str(value) {
            return Ok(Self::Ip(ip));
        }

        let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(AddressError::EmptyDomain);
        }

        Ok(Self::Domain(domain))
    }
}

impl fmt::Display for DestinationHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub host: DestinationHost,
    pub port: u16,
    #[serde(default)]
    pub network: Network,
}

impl Destination {
    #[must_use]
    pub fn tcp(host: DestinationHost, port: u16) -> Self {
        Self {
            host,
            port,
            network: Network::Tcp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionContext {
    pub inbound_tag: String,
    pub destination: Destination,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub user: Option<String>,
    pub protocol: Option<String>,
    pub attributes: HashMap<String, String>,
}

impl SessionContext {
    #[must_use]
    pub fn new(inbound_tag: impl Into<String>, destination: Destination) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            destination,
            source_ip: None,
            source_port: None,
            user: None,
            protocol: None,
            attributes: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_ip = Some(source_ip);
        self
    }

    #[must_use]
    pub fn with_source_port(mut self, source_port: u16) -> Self {
        self.source_port = Some(source_port);
        self
    }

    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(name.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_hosts() {
        let host = DestinationHost::parse("127.0.0.1").unwrap();
        assert_eq!(host.to_string(), "127.0.0.1");
    }

    #[test]
    fn normalizes_domain_hosts() {
        let host = DestinationHost::parse("Example.COM.").unwrap();
        assert_eq!(host, DestinationHost::Domain("example.com".to_owned()));
    }

    #[test]
    fn rejects_empty_domains() {
        assert_eq!(DestinationHost::parse("."), Err(AddressError::EmptyDomain));
    }
}
