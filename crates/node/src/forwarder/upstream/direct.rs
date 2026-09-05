use super::{resolve_target, TargetAddress, UpstreamConnector, UpstreamError, UpstreamErrorCode};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct DirectConnector;

#[async_trait]
impl UpstreamConnector for DirectConnector {
    async fn connect(
        &self,
        target: &TargetAddress,
        source_ipv4: Option<Ipv4Addr>,
    ) -> Result<TcpStream, UpstreamError> {
        let target_string = target.to_string();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            crate::forwarder::outbound::tcp_connect(&target_string, source_ipv4, 5),
        )
        .await;
        match result {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => {
                let code = match resolve_target(target).await {
                    Ok(addresses) if addresses.is_empty() => {
                        UpstreamErrorCode::Socks5HostUnreachable
                    }
                    _ if error.to_string().to_ascii_lowercase().contains("refused") => {
                        UpstreamErrorCode::UpstreamConnectionRefused
                    }
                    _ => UpstreamErrorCode::Unknown,
                };
                Err(UpstreamError::new(code, error.to_string()))
            }
            Err(_) => Err(UpstreamError::new(
                UpstreamErrorCode::UpstreamConnectTimeout,
                "direct upstream connect timed out",
            )),
        }
    }
}
