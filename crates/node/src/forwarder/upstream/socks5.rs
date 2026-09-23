use super::{resolve_target, TargetAddress, UpstreamConnector, UpstreamError, UpstreamErrorCode};
use async_trait::async_trait;
use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::{Error as SocksError, TargetAddr};

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const SOCKS5_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const SOCKS5_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

pub struct Socks5Connector {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub remote_dns: bool,
}

#[async_trait]
impl UpstreamConnector for Socks5Connector {
    async fn connect(
        &self,
        target: &TargetAddress,
        source_ipv4: Option<Ipv4Addr>,
    ) -> Result<TcpStream, UpstreamError> {
        let proxy = format_endpoint(&self.host, self.port);
        let socket = tokio::time::timeout(
            PROXY_CONNECT_TIMEOUT,
            crate::forwarder::outbound::tcp_connect(&proxy, source_ipv4, 5),
        )
        .await
        .map_err(|_| {
            UpstreamError::new(
                UpstreamErrorCode::UpstreamConnectTimeout,
                "SOCKS5 proxy TCP connect timed out",
            )
        })?
        .map_err(map_proxy_connect_error)?;

        let target = self.target_for_proxy(target).await?;
        let negotiated = tokio::time::timeout(SOCKS5_CONNECT_TIMEOUT, async {
            match (&self.username, &self.password) {
                (Some(username), Some(password)) => {
                    Socks5Stream::connect_with_password_and_socket(
                        socket, target, username, password,
                    )
                    .await
                }
                (None, None) => Socks5Stream::connect_with_socket(socket, target).await,
                _ => unreachable!("credential pair validated at connector construction"),
            }
        })
        .await
        .map_err(|_| {
            UpstreamError::new(
                UpstreamErrorCode::UpstreamConnectTimeout,
                "SOCKS5 negotiation or CONNECT timed out",
            )
        })?
        .map_err(map_socks_error)?;

        let stream = negotiated.into_inner();
        let _ = stream.set_nodelay(true);
        crate::forwarder::outbound::apply_keepalive(&stream, "SOCKS5 upstream");
        Ok(stream)
    }
}

impl Socks5Connector {
    async fn target_for_proxy(
        &self,
        target: &TargetAddress,
    ) -> Result<TargetAddr<'static>, UpstreamError> {
        match target {
            TargetAddress::Ip(addr) => Ok(TargetAddr::Ip(*addr)),
            TargetAddress::Domain(host, port) if self.remote_dns => {
                Ok(TargetAddr::Domain(Cow::Owned(host.clone()), *port))
            }
            TargetAddress::Domain(_, _) => resolve_target(target)
                .await?
                .into_iter()
                .next()
                .map(TargetAddr::Ip)
                .ok_or_else(|| {
                    UpstreamError::new(
                        UpstreamErrorCode::Socks5HostUnreachable,
                        "target domain resolved to no addresses",
                    )
                }),
        }
    }
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn map_socks_error(error: SocksError) -> UpstreamError {
    let code = match error {
        SocksError::PasswordAuthFailure(_)
        | SocksError::AuthorizationRequired
        | SocksError::NoAcceptableAuthMethods
        | SocksError::IdentdAuthFailure
        | SocksError::InvalidUserIdAuthFailure => UpstreamErrorCode::Socks5AuthFailed,
        SocksError::NetworkUnreachable => UpstreamErrorCode::Socks5NetworkUnreachable,
        SocksError::HostUnreachable => UpstreamErrorCode::Socks5HostUnreachable,
        SocksError::ConnectionRefused => UpstreamErrorCode::Socks5TargetUnreachable,
        SocksError::TtlExpired => UpstreamErrorCode::Socks5TtlExpired,
        SocksError::GeneralSocksServerFailure
        | SocksError::ConnectionNotAllowedByRuleset
        | SocksError::CommandNotSupported
        | SocksError::AddressTypeNotSupported => UpstreamErrorCode::Socks5ConnectRejected,
        SocksError::ProxyServerUnreachable => UpstreamErrorCode::UpstreamConnectionRefused,
        SocksError::Io(ref io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            UpstreamErrorCode::UpstreamConnectionRefused
        }
        SocksError::Io(_) => UpstreamErrorCode::Unknown,
        _ => UpstreamErrorCode::Socks5HandshakeFailed,
    };
    UpstreamError::new(code, error.to_string())
}

fn map_proxy_connect_error(error: crate::forwarder::outbound::OutboundError) -> UpstreamError {
    use crate::forwarder::outbound::OutboundError;

    let code = match &error {
        OutboundError::Connect(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            UpstreamErrorCode::UpstreamConnectionRefused
        }
        OutboundError::Connect(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::AddrNotAvailable
            ) =>
        {
            UpstreamErrorCode::Socks5NetworkUnreachable
        }
        _ => UpstreamErrorCode::Unknown,
    };
    UpstreamError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn stalled_upstream_handshake_times_out_without_exposing_password() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let connector = Socks5Connector {
            host: address.ip().to_string(),
            port: address.port(),
            username: Some("up-user".into()),
            password: Some("never-print-this".into()),
            remote_dns: true,
        };
        let error = connector
            .connect(&TargetAddress::Domain("example.com".into(), 443), None)
            .await
            .unwrap_err();
        assert_eq!(error.code, UpstreamErrorCode::UpstreamConnectTimeout);
        assert!(!error.to_string().contains("never-print-this"));
        server.abort();
    }
}
