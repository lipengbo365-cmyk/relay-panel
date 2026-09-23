mod direct;
mod socks5;

use async_trait::async_trait;
use relay_shared::protocol::UpstreamConfig;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamErrorCode {
    UpstreamConnectTimeout,
    UpstreamConnectionRefused,
    Socks5HandshakeFailed,
    Socks5AuthFailed,
    Socks5ConnectRejected,
    Socks5TargetUnreachable,
    Socks5NetworkUnreachable,
    Socks5HostUnreachable,
    Socks5TtlExpired,
    InvalidConfig,
    Unknown,
}

impl UpstreamErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamConnectTimeout => "UPSTREAM_CONNECT_TIMEOUT",
            Self::UpstreamConnectionRefused => "UPSTREAM_CONNECTION_REFUSED",
            Self::Socks5HandshakeFailed => "SOCKS5_HANDSHAKE_FAILED",
            Self::Socks5AuthFailed => "SOCKS5_AUTH_FAILED",
            Self::Socks5ConnectRejected => "SOCKS5_CONNECT_REJECTED",
            Self::Socks5TargetUnreachable => "SOCKS5_TARGET_UNREACHABLE",
            Self::Socks5NetworkUnreachable => "SOCKS5_NETWORK_UNREACHABLE",
            Self::Socks5HostUnreachable => "SOCKS5_HOST_UNREACHABLE",
            Self::Socks5TtlExpired => "SOCKS5_TTL_EXPIRED",
            Self::InvalidConfig => "INVALID_UPSTREAM_CONFIG",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug)]
pub struct UpstreamError {
    pub code: UpstreamErrorCode,
    pub message: String,
}

impl UpstreamError {
    pub fn new(code: UpstreamErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// RFC 1928 reply code to send to the inbound SOCKS client.
    pub fn socks5_reply(&self) -> u8 {
        match self.code {
            UpstreamErrorCode::Socks5NetworkUnreachable => 0x03,
            UpstreamErrorCode::Socks5HostUnreachable => 0x04,
            UpstreamErrorCode::Socks5ConnectRejected
            | UpstreamErrorCode::Socks5TargetUnreachable => 0x05,
            UpstreamErrorCode::Socks5TtlExpired => 0x06,
            _ => 0x01,
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UpstreamError {}

#[async_trait]
pub trait UpstreamConnector: Send + Sync {
    async fn connect(
        &self,
        target: &TargetAddress,
        source_ipv4: Option<Ipv4Addr>,
    ) -> Result<TcpStream, UpstreamError>;
}

pub fn connector_from_config(
    config: &UpstreamConfig,
) -> Result<Box<dyn UpstreamConnector>, UpstreamError> {
    match config {
        UpstreamConfig::Direct => Ok(Box::new(direct::DirectConnector)),
        UpstreamConfig::Socks5 {
            host,
            port,
            username,
            password,
            remote_dns,
            ..
        } => {
            if host.trim().is_empty() || *port == 0 || username.is_some() != password.is_some() {
                return Err(UpstreamError::new(
                    UpstreamErrorCode::InvalidConfig,
                    "invalid SOCKS5 upstream configuration",
                ));
            }
            Ok(Box::new(socks5::Socks5Connector {
                host: host.clone(),
                port: *port,
                username: username.clone(),
                password: password.as_ref().map(|value| value.expose().to_owned()),
                remote_dns: *remote_dns,
            }))
        }
    }
}

pub async fn resolve_target(target: &TargetAddress) -> Result<Vec<SocketAddr>, UpstreamError> {
    match target {
        TargetAddress::Ip(addr) => Ok(vec![*addr]),
        TargetAddress::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .map(|iter| iter.collect())
            .map_err(|e| {
                UpstreamError::new(UpstreamErrorCode::Socks5HostUnreachable, e.to_string())
            }),
    }
}

pub fn socket_target(ip: IpAddr, port: u16) -> TargetAddress {
    TargetAddress::Ip(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::SecretString;

    fn socks(
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> UpstreamConfig {
        UpstreamConfig::Socks5 {
            resource_id: 1,
            resource_name: "test".into(),
            host: host.into(),
            port,
            username: username.map(str::to_owned),
            password: password.map(SecretString::new),
            remote_dns: true,
        }
    }

    #[test]
    fn malformed_socks5_upstream_configs_fail_closed() {
        for config in [
            socks("", 1080, None, None),
            socks("127.0.0.1", 0, None, None),
            socks("127.0.0.1", 1080, Some("user"), None),
            socks("127.0.0.1", 1080, None, Some("password")),
        ] {
            let error = connector_from_config(&config).err().expect("must reject");
            assert_eq!(error.code, UpstreamErrorCode::InvalidConfig);
        }
    }
}
