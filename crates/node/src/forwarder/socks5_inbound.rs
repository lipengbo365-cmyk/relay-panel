use super::gate::RuleGate;
use super::limiter::RateLimit;
use super::upstream::{connector_from_config, socket_target, TargetAddress};
use crate::reporter::{ConnectionTracker, TrafficCounter};
use relay_shared::protocol::{Socks5InboundAuth, UpstreamConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CAP_WARN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
enum ClientErrorCode {
    InvalidClientHandshake,
    ClientAuthFailed,
    Unknown,
}

impl ClientErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidClientHandshake => "INVALID_CLIENT_HANDSHAKE",
            Self::ClientAuthFailed => "CLIENT_AUTH_FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug)]
struct ClientProtocolError {
    code: ClientErrorCode,
    message: String,
}

impl ClientProtocolError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ClientErrorCode::InvalidClientHandshake,
            message: message.into(),
        }
    }

    fn auth(message: impl Into<String>) -> Self {
        Self {
            code: ClientErrorCode::ClientAuthFailed,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ClientProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ClientProtocolError {}

impl From<std::io::Error> for ClientProtocolError {
    fn from(error: std::io::Error) -> Self {
        Self {
            code: ClientErrorCode::Unknown,
            message: error.to_string(),
        }
    }
}

#[derive(Clone)]
struct UpstreamLogContext {
    resource_id: i64,
    resource_name: String,
    proxy_host: String,
    proxy_port: u16,
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_socks5_listener(
    listener: TcpListener,
    auth: Socks5InboundAuth,
    upstream: UpstreamConfig,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    rule_id: i64,
    source_ipv4: Option<Ipv4Addr>,
    gate: RuleGate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let UpstreamConfig::Socks5 {
        resource_id,
        resource_name,
        host,
        port,
        ..
    } = &upstream
    else {
        return Err(
            "SOCKS5 inbound requires a SOCKS5 upstream; direct fallback is forbidden".into(),
        );
    };
    let upstream_log = UpstreamLogContext {
        resource_id: *resource_id,
        resource_name: resource_name.clone(),
        proxy_host: host.clone(),
        proxy_port: *port,
    };
    let connector =
        Arc::<dyn super::upstream::UpstreamConnector>::from(connector_from_config(&upstream)?);
    let listen_addr = listener.local_addr()?;
    tracing::info!("SOCKS5 listening on {} (rule {})", listen_addr, rule_id);
    let mut last_cap_warn = None;

    loop {
        let (inbound, client_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(error) if super::tcp::is_transient_accept_error(&error) => {
                tracing::warn!(
                    rule_id,
                    listener = %listen_addr,
                    %error,
                    "transient SOCKS5 accept error; retrying in 100ms"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(Box::new(error)),
        };
        let Some(conn_guard) = gate.admit() else {
            drop(inbound);
            let now = std::time::Instant::now();
            if last_cap_warn.is_none_or(|last| now.duration_since(last) >= CAP_WARN_INTERVAL) {
                last_cap_warn = Some(now);
                tracing::warn!(
                    rule_id,
                    live = gate.live(),
                    max = gate.max_connections.unwrap_or(0),
                    "SOCKS5 connection cap reached"
                );
            }
            continue;
        };
        let _ = inbound.set_nodelay(true);
        super::outbound::apply_keepalive(&inbound, "SOCKS5 accept");
        let auth = auth.clone();
        let connector = connector.clone();
        let upstream_log = upstream_log.clone();
        let rate_limit = rate_limit.clone();
        let counter = counter.clone();
        let connections = connections.clone();
        let mut gate = gate.clone();
        tokio::spawn(async move {
            let _connection = connections.tcp_handle();
            let _admission = conn_guard;
            tokio::select! {
                _ = gate.cancelled() => {}
                result = handle_connection(
                    inbound,
                    client_addr,
                    &auth,
                    connector.as_ref(),
                    &upstream_log,
                    source_ipv4,
                    rate_limit,
                    counter,
                    rule_id,
                ) => {
                    if let Err(error) = result {
                        tracing::debug!(rule_id, client = %client_addr, "SOCKS5 session ended with error: {error}");
                    }
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    auth: &Socks5InboundAuth,
    connector: &dyn super::upstream::UpstreamConnector,
    upstream_log: &UpstreamLogContext,
    source_ipv4: Option<Ipv4Addr>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    rule_id: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target =
        match tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, negotiate(&mut inbound, auth)).await {
            Ok(Ok(target)) => target,
            Ok(Err(error)) => {
                tracing::warn!(
                    rule_id,
                    client = %client_addr,
                    error_stage = "client_handshake",
                    error_code = error.code.as_str(),
                    "SOCKS5 client negotiation rejected: {error}"
                );
                return Err(Box::new(error));
            }
            Err(_) => {
                let _ = send_reply(&mut inbound, 0x01, None).await;
                tracing::warn!(
                    rule_id,
                    client = %client_addr,
                    error_stage = "client_handshake",
                    error_code = "INVALID_CLIENT_HANDSHAKE",
                    "inbound SOCKS5 handshake timed out"
                );
                return Err(Box::new(ClientProtocolError::invalid(
                    "inbound SOCKS5 handshake timed out",
                )));
            }
        };

    let started = Instant::now();
    let outbound = match connector.connect(&target, source_ipv4).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = send_reply(&mut inbound, error.socks5_reply(), None).await;
            tracing::warn!(
                rule_id,
                client = %client_addr,
                target = %target,
                resource_id = upstream_log.resource_id,
                resource_name = %upstream_log.resource_name,
                proxy_host = %upstream_log.proxy_host,
                proxy_port = upstream_log.proxy_port,
                error_stage = "upstream_socks5_connect",
                error_code = error.code.as_str(),
                latency_ms = started.elapsed().as_millis() as u64,
                "SOCKS5 upstream CONNECT failed"
            );
            return Err(Box::new(error));
        }
    };
    let bound = outbound.local_addr().ok();
    send_reply(&mut inbound, 0x00, bound).await?;

    // Handshake bytes are deliberately excluded; only successfully established
    // application tunnel bytes enter the existing accounting and quota chain.
    super::tcp::relay_tcp_stream(inbound, outbound, client_addr, rate_limit, counter, rule_id).await
}

async fn negotiate(
    stream: &mut TcpStream,
    auth: &Socks5InboundAuth,
) -> Result<TargetAddress, ClientProtocolError> {
    let version = stream.read_u8().await?;
    let method_count = stream.read_u8().await? as usize;
    if version != 0x05 || method_count == 0 {
        return Err(ClientProtocolError::invalid("invalid SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    let required_method = match auth {
        Socks5InboundAuth::NoAuth => 0x00,
        Socks5InboundAuth::UsernamePassword { .. } => 0x02,
    };
    if !methods.contains(&required_method) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(ClientProtocolError::auth(
            "client offered no acceptable authentication method",
        ));
    }
    stream.write_all(&[0x05, required_method]).await?;

    if let Socks5InboundAuth::UsernamePassword { username, password } = auth {
        let auth_version = stream.read_u8().await?;
        let username_len = stream.read_u8().await? as usize;
        let mut provided_username = vec![0u8; username_len];
        stream.read_exact(&mut provided_username).await?;
        let password_len = stream.read_u8().await? as usize;
        let mut provided_password = vec![0u8; password_len];
        stream.read_exact(&mut provided_password).await?;
        let valid = auth_version == 0x01
            && constant_time_eq(&provided_username, username.as_bytes())
            && constant_time_eq(&provided_password, password.expose().as_bytes());
        stream
            .write_all(&[0x01, if valid { 0x00 } else { 0x01 }])
            .await?;
        if !valid {
            return Err(ClientProtocolError::auth(
                "SOCKS5 username/password authentication failed",
            ));
        }
    }

    let version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    if version != 0x05 || reserved != 0x00 {
        send_reply(stream, 0x01, None).await?;
        return Err(ClientProtocolError::invalid(
            "invalid SOCKS5 request header",
        ));
    }
    if command != 0x01 {
        send_reply(stream, 0x07, None).await?;
        return Err(ClientProtocolError::invalid(
            "SOCKS5 command is not CONNECT",
        ));
    }
    let target = match address_type {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            socket_target(IpAddr::V4(octets.into()), port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            socket_target(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                send_reply(stream, 0x08, None).await?;
                return Err(ClientProtocolError::invalid("empty SOCKS5 domain"));
            }
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain)
                .map_err(|_| ClientProtocolError::invalid("invalid SOCKS5 domain"))?;
            TargetAddress::Domain(domain, port)
        }
        _ => {
            send_reply(stream, 0x08, None).await?;
            return Err(ClientProtocolError::invalid(
                "unsupported SOCKS5 address type",
            ));
        }
    };
    Ok(target)
}

async fn send_reply(
    stream: &mut TcpStream,
    reply: u8,
    bound: Option<SocketAddr>,
) -> std::io::Result<()> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut response = vec![0x05, reply, 0x00];
    match bound.ip() {
        IpAddr::V4(ip) => {
            response.push(0x01);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(0x04);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&response).await
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    // RFC 1929 lengths are one byte, so both values are at most 255 bytes.
    // Always walk the full protocol maximum; iterating only max(actual lengths)
    // leaks the longer credential length through timing.
    let mut diff = left.len() ^ right.len();
    for index in 0..=u8::MAX as usize {
        diff |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::gate::RuleRuntime;
    use crate::forwarder::upstream::{UpstreamError, UpstreamErrorCode};
    use async_trait::async_trait;
    use relay_shared::protocol::SecretString;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_socks::tcp::Socks5Stream;

    #[test]
    fn credential_comparison_checks_content_and_length() {
        assert!(constant_time_eq(b"alice", b"alice"));
        assert!(!constant_time_eq(b"alice", b"alicf"));
        assert!(!constant_time_eq(b"alice", b"alice-long"));
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn malformed_frame_is_bounded(frame: &[u8], auth: Socks5InboundAuth) {
        let (mut client, mut server) = connected_pair().await;
        client.write_all(frame).await.unwrap();
        client.shutdown().await.unwrap();
        let outcome =
            tokio::time::timeout(Duration::from_millis(500), negotiate(&mut server, &auth))
                .await
                .expect("malformed input must not wait forever");
        assert!(outcome.is_err(), "malformed frame unexpectedly succeeded");
    }

    #[tokio::test]
    async fn malformed_inbound_matrix_never_panics_or_waits_unbounded() {
        let no_auth = Socks5InboundAuth::NoAuth;
        let password_auth = Socks5InboundAuth::UsernamePassword {
            username: "relay-user".into(),
            password: SecretString::new("relay-password"),
        };
        let frames: Vec<(&str, Vec<u8>, Socks5InboundAuth)> = vec![
            ("empty greeting", vec![], no_auth.clone()),
            ("method count zero", vec![5, 0], no_auth.clone()),
            ("non-v5 greeting", vec![4, 1, 0], no_auth.clone()),
            ("truncated methods", vec![5, 2, 0], no_auth.clone()),
            (
                "malformed RFC1929",
                vec![5, 1, 2, 2, 1, b'x'],
                password_auth.clone(),
            ),
            (
                "empty username",
                vec![5, 1, 2, 1, 0, 1, b'x'],
                password_auth.clone(),
            ),
            (
                "empty password",
                vec![5, 1, 2, 1, 1, b'x', 0],
                password_auth.clone(),
            ),
            ("illegal ATYP", vec![5, 1, 0, 5, 1, 0, 9], no_auth.clone()),
            (
                "truncated IPv4",
                vec![5, 1, 0, 5, 1, 0, 1, 127, 0],
                no_auth.clone(),
            ),
            (
                "truncated IPv6",
                vec![5, 1, 0, 5, 1, 0, 4, 0, 0],
                no_auth.clone(),
            ),
            (
                "truncated domain",
                vec![5, 1, 0, 5, 1, 0, 3, 4, b't', b'e'],
                no_auth.clone(),
            ),
            (
                "empty domain",
                vec![5, 1, 0, 5, 1, 0, 3, 0],
                no_auth.clone(),
            ),
            (
                "CONNECT missing port",
                vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1],
                no_auth.clone(),
            ),
            (
                "BIND",
                vec![5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80],
                no_auth.clone(),
            ),
            (
                "UDP ASSOCIATE",
                vec![5, 1, 0, 5, 3, 0, 1, 127, 0, 0, 1, 0, 80],
                no_auth,
            ),
        ];
        for (name, frame, auth) in frames {
            tokio::time::timeout(
                Duration::from_secs(1),
                malformed_frame_is_bounded(&frame, auth),
            )
            .await
            .unwrap_or_else(|_| panic!("case timed out: {name}"));
        }
    }

    #[tokio::test]
    async fn protocol_maximum_lengths_are_bounded_and_accepted() {
        let username = "u".repeat(255);
        let password = "p".repeat(255);
        let auth = Socks5InboundAuth::UsernamePassword {
            username: username.clone(),
            password: SecretString::new(password.clone()),
        };
        let mut frame = vec![5, 255];
        frame.extend(std::iter::repeat_n(2, 255));
        frame.extend([1, 255]);
        frame.extend(username.as_bytes());
        frame.push(255);
        frame.extend(password.as_bytes());
        frame.extend([5, 1, 0, 3, 1, b'x', 0, 80]);
        let (mut client, mut server) = connected_pair().await;
        client.write_all(&frame).await.unwrap();
        let target = tokio::time::timeout(Duration::from_secs(1), negotiate(&mut server, &auth))
            .await
            .expect("maximum legal lengths stay bounded")
            .expect("maximum legal lengths are valid");
        assert_eq!(target, TargetAddress::Domain("x".into(), 80));
    }

    #[tokio::test]
    async fn slow_and_half_closed_handshakes_are_bounded_by_the_session_timeout() {
        let (mut slow_client, mut slow_server) = connected_pair().await;
        slow_client.write_u8(5).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            negotiate(&mut slow_server, &Socks5InboundAuth::NoAuth),
        )
        .await
        .is_err());
        drop(slow_client);

        malformed_frame_is_bounded(&[5, 1, 0], Socks5InboundAuth::NoAuth).await;
    }

    struct CountingConnector(AtomicUsize);

    #[async_trait]
    impl super::super::upstream::UpstreamConnector for CountingConnector {
        async fn connect(
            &self,
            _target: &TargetAddress,
            _source_ipv4: Option<Ipv4Addr>,
        ) -> Result<TcpStream, UpstreamError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(UpstreamError::new(
                UpstreamErrorCode::Unknown,
                "test connector must not run",
            ))
        }
    }

    #[tokio::test]
    async fn inbound_auth_failure_never_opens_an_upstream_connection() {
        let connector = CountingConnector(AtomicUsize::new(0));
        let (mut client, server) = connected_pair().await;
        client
            .write_all(&[
                5, 1, 2, 1, 10, b'r', b'e', b'l', b'a', b'y', b'-', b'u', b's', b'e', b'r', 5,
                b'w', b'r', b'o', b'n', b'g',
            ])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let result = handle_connection(
            server,
            "127.0.0.1:12345".parse().unwrap(),
            &Socks5InboundAuth::UsernamePassword {
                username: "relay-user".into(),
                password: SecretString::new("relay-password"),
            },
            &connector,
            &UpstreamLogContext {
                resource_id: 1,
                resource_name: "test".into(),
                proxy_host: "127.0.0.1".into(),
                proxy_port: 1080,
            },
            None,
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            99,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(connector.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn socks5_listener_rejects_direct_upstream_at_its_own_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runtime = RuleRuntime::new();
        let result = serve_socks5_listener(
            listener,
            Socks5InboundAuth::NoAuth,
            UpstreamConfig::Direct,
            RateLimit::Unlimited,
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            100,
            None,
            runtime.gate(None),
        )
        .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("direct fallback is forbidden"));
    }

    async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (address, task)
    }

    async fn spawn_http_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while request.len() < 8192 && stream.read_exact(&mut byte).await.is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(request.starts_with(b"GET /probe HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nrelay-socks5-http-ok",
                )
                .await
                .unwrap();
        });
        (address, task)
    }

    async fn spawn_mock_upstream(
        expected_password: &'static str,
    ) -> (
        SocketAddr,
        oneshot::Receiver<u8>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (address_type_tx, address_type_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let version = client.read_u8().await.unwrap();
            let count = client.read_u8().await.unwrap() as usize;
            let mut methods = vec![0; count];
            client.read_exact(&mut methods).await.unwrap();
            assert_eq!(version, 5);
            assert!(methods.contains(&2));
            client.write_all(&[5, 2]).await.unwrap();

            assert_eq!(client.read_u8().await.unwrap(), 1);
            let user_len = client.read_u8().await.unwrap() as usize;
            let mut user = vec![0; user_len];
            client.read_exact(&mut user).await.unwrap();
            let password_len = client.read_u8().await.unwrap() as usize;
            let mut password = vec![0; password_len];
            client.read_exact(&mut password).await.unwrap();
            let auth_ok = user == b"upstream-user" && password == expected_password.as_bytes();
            client
                .write_all(&[1, if auth_ok { 0 } else { 1 }])
                .await
                .unwrap();
            if !auth_ok {
                return;
            }

            let mut header = [0u8; 4];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..3], &[5, 1, 0]);
            let address_type = header[3];
            let _ = address_type_tx.send(address_type);
            let target = match address_type {
                1 => {
                    let mut octets = [0; 4];
                    client.read_exact(&mut octets).await.unwrap();
                    let port = client.read_u16().await.unwrap();
                    SocketAddr::new(IpAddr::V4(octets.into()), port)
                }
                3 => {
                    let len = client.read_u8().await.unwrap() as usize;
                    let mut host = vec![0; len];
                    client.read_exact(&mut host).await.unwrap();
                    let port = client.read_u16().await.unwrap();
                    let host = String::from_utf8(host).unwrap();
                    let resolved = tokio::net::lookup_host((host.as_str(), port))
                        .await
                        .unwrap()
                        .find(|address| address.is_ipv4())
                        .unwrap();
                    resolved
                }
                4 => {
                    let mut octets = [0; 16];
                    client.read_exact(&mut octets).await.unwrap();
                    let port = client.read_u16().await.unwrap();
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
                }
                _ => panic!("unexpected address type"),
            };
            match TcpStream::connect(target).await {
                Ok(mut target) => {
                    client
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                }
                Err(_) => {
                    let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                }
            }
        });
        (address, address_type_rx, task)
    }

    async fn spawn_concurrent_no_auth_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let outcome: std::io::Result<()> = async {
                        if client.read_u8().await? != 5 {
                            return Ok(());
                        }
                        let count = client.read_u8().await? as usize;
                        let mut methods = vec![0; count];
                        client.read_exact(&mut methods).await?;
                        if !methods.contains(&0) {
                            client.write_all(&[5, 0xff]).await?;
                            return Ok(());
                        }
                        client.write_all(&[5, 0]).await?;
                        let mut header = [0; 4];
                        client.read_exact(&mut header).await?;
                        if header[..3] != [5, 1, 0] {
                            return Ok(());
                        }
                        let target = match header[3] {
                            1 => {
                                let mut octets = [0; 4];
                                client.read_exact(&mut octets).await?;
                                SocketAddr::new(IpAddr::V4(octets.into()), client.read_u16().await?)
                            }
                            4 => {
                                let mut octets = [0; 16];
                                client.read_exact(&mut octets).await?;
                                SocketAddr::new(
                                    IpAddr::V6(Ipv6Addr::from(octets)),
                                    client.read_u16().await?,
                                )
                            }
                            _ => return Ok(()),
                        };
                        let mut target = TcpStream::connect(target).await?;
                        client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                        Ok(())
                    }
                    .await;
                    let _ = outcome;
                });
            }
        });
        (address, task)
    }

    #[cfg(target_os = "linux")]
    fn process_resources() -> (usize, u64) {
        let fds = std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count())
            .unwrap_or(0);
        let rss_kib = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:")?
                        .split_whitespace()
                        .next()?
                        .parse()
                        .ok()
                })
            })
            .unwrap_or(0);
        (fds, rss_kib)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "stage-2 stress audit; run explicitly"]
    async fn stress_100_500_1000_short_connections_release_all_resources() {
        let (echo, echo_task) = spawn_echo().await;
        let (upstream, upstream_task) = spawn_concurrent_no_auth_upstream().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = listener.local_addr().unwrap();
        let counter = Arc::new(TrafficCounter::new());
        let tracker = Arc::new(ConnectionTracker::new());
        let runtime = RuleRuntime::new();
        let observed_gate = runtime.gate(None);
        let relay_task = tokio::spawn(serve_socks5_listener(
            listener,
            Socks5InboundAuth::NoAuth,
            UpstreamConfig::Socks5 {
                resource_id: 1,
                resource_name: "stress".into(),
                host: upstream.ip().to_string(),
                port: upstream.port(),
                username: None,
                password: None,
                remote_dns: true,
            },
            RateLimit::Unlimited,
            counter.clone(),
            tracker.clone(),
            4242,
            None,
            observed_gate.clone(),
        ));
        let baseline = process_resources();

        for concurrency in [100usize, 500, 1000] {
            let started = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for sequence in 0..concurrency {
                tasks.spawn(async move {
                    let socket = TcpStream::connect(relay).await.unwrap();
                    let mut tunnel = Socks5Stream::connect_with_socket(socket, echo)
                        .await
                        .unwrap();
                    let payload = (sequence as u64).to_be_bytes();
                    tunnel.write_all(&payload).await.unwrap();
                    let mut echoed = [0; 8];
                    tunnel.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(echoed, payload);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if tracker.current().await == 0 && observed_gate.live() == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("connection tracker and RuleGate must drain");
            let resources = process_resources();
            eprintln!(
                "stress concurrency={concurrency} elapsed_ms={} fd={} rss_kib={}",
                started.elapsed().as_millis(),
                resources.0,
                resources.1
            );
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        let final_resources = process_resources();
        assert!(
            final_resources.0 <= baseline.0 + 32,
            "FD leak: baseline={} final={}",
            baseline.0,
            final_resources.0
        );
        assert!(
            final_resources.1 <= baseline.1 + 128 * 1024,
            "RSS grew by more than 128 MiB: baseline={}KiB final={}KiB",
            baseline.1,
            final_resources.1
        );
        assert_eq!(tracker.current().await, 0);
        assert_eq!(observed_gate.live(), 0);
        let traffic = counter.snapshot().await;
        let entry = traffic
            .entries
            .iter()
            .find(|entry| entry.rule_id == 4242)
            .unwrap();
        assert!(entry.upload >= 1600 * 8);
        assert!(entry.download >= 1600 * 8);

        runtime.cancel_all();
        relay_task.abort();
        upstream_task.abort();
        echo_task.abort();
    }

    async fn spawn_relay(
        upstream: SocketAddr,
        upstream_password: &str,
    ) -> (
        SocketAddr,
        Arc<TrafficCounter>,
        RuleRuntime,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_relay_with_auth(
            upstream,
            upstream_password,
            Socks5InboundAuth::UsernamePassword {
                username: "relay-user".into(),
                password: SecretString::new("relay-password"),
            },
        )
        .await
    }

    async fn spawn_relay_with_auth(
        upstream: SocketAddr,
        upstream_password: &str,
        auth: Socks5InboundAuth,
    ) -> (
        SocketAddr,
        Arc<TrafficCounter>,
        RuleRuntime,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let counter = Arc::new(TrafficCounter::new());
        let task_counter = counter.clone();
        let upstream_password = upstream_password.to_owned();
        let runtime = RuleRuntime::new();
        let gate = runtime.gate(None);
        let task = tokio::spawn(async move {
            let _ = serve_socks5_listener(
                listener,
                auth,
                UpstreamConfig::Socks5 {
                    resource_id: 7,
                    resource_name: "mock".into(),
                    host: upstream.ip().to_string(),
                    port: upstream.port(),
                    username: Some("upstream-user".into()),
                    password: Some(SecretString::new(upstream_password)),
                    remote_dns: true,
                },
                RateLimit::Unlimited,
                task_counter,
                Arc::new(ConnectionTracker::new()),
                42,
                None,
                gate,
            )
            .await;
        });
        (address, counter, runtime, task)
    }

    #[tokio::test]
    async fn full_socks5_to_socks5_connect_chain_works_and_counts_traffic() {
        let (echo, echo_task) = spawn_echo().await;
        let (upstream, address_type, upstream_task) = spawn_mock_upstream("upstream-pass").await;
        let (relay, counter, runtime, relay_task) = spawn_relay(upstream, "upstream-pass").await;

        assert!(echo.port() > 0);
        assert!(upstream.port() > 0);
        assert!(relay.port() > 0);
        assert_ne!(relay, upstream);
        assert_ne!(upstream, echo);

        let socket = TcpStream::connect(relay).await.unwrap();
        let mut tunnel = Socks5Stream::connect_with_password_and_socket(
            socket,
            ("localhost", echo.port()),
            "relay-user",
            "relay-password",
        )
        .await
        .expect("the two authenticated SOCKS5 hops should establish");
        assert_eq!(
            address_type.await.unwrap(),
            3,
            "domain must be resolved upstream"
        );
        let proxy_bound = tunnel.target_addr().to_string();
        assert!(!proxy_bound.is_empty());
        assert!(proxy_bound.contains(':'));

        let payload = b"relay-panel-socks5-e2e";
        tunnel.write_all(payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert_eq!(received.len(), 22);
        drop(tunnel);
        tokio::task::yield_now().await;

        let snapshot = counter.snapshot().await;
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.rule_id == 42)
            .unwrap();
        assert_eq!(entry.rule_id, 42);
        assert!(entry.upload >= payload.len() as u64);
        assert!(entry.download >= payload.len() as u64);
        assert_eq!(entry.upload, entry.download);
        assert!(runtime.cancel_all() <= 1);

        relay_task.abort();
        upstream_task.abort();
        echo_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn curl_reaches_http_server_through_relay_and_upstream_socks5() {
        let (http, http_task) = spawn_http_server().await;
        let (upstream, address_type, upstream_task) = spawn_mock_upstream("upstream-pass").await;
        let (relay, counter, runtime, relay_task) = spawn_relay(upstream, "upstream-pass").await;
        let proxy = format!("socks5h://{}", relay);
        let url = format!("http://localhost:{}/probe", http.port());

        let output = tokio::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--proxy",
                &proxy,
                "--proxy-user",
                "relay-user:relay-password",
                &url,
            ])
            .output()
            .await
            .expect("curl must be installed in the Linux test environment");
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "relay-socks5-http-ok"
        );
        assert_eq!(
            address_type.await.unwrap(),
            3,
            "socks5h must preserve the domain"
        );
        http_task.await.unwrap();
        tokio::task::yield_now().await;
        let entry = counter
            .snapshot()
            .await
            .entries
            .into_iter()
            .find(|entry| entry.rule_id == 42)
            .unwrap();
        assert!(entry.upload > 0);
        assert!(entry.download > 0);

        runtime.cancel_all();
        relay_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn wrong_inbound_or_upstream_password_fails_closed() {
        let (echo, echo_task) = spawn_echo().await;
        let (upstream, _, upstream_task) = spawn_mock_upstream("upstream-pass").await;
        let (relay, _, _runtime, relay_task) = spawn_relay(upstream, "upstream-pass").await;
        let socket = TcpStream::connect(relay).await.unwrap();
        let inbound_failure = Socks5Stream::connect_with_password_and_socket(
            socket,
            echo,
            "relay-user",
            "wrong-password",
        )
        .await;
        assert!(inbound_failure.is_err());
        relay_task.abort();
        upstream_task.abort();

        let (upstream2, _, upstream_task2) = spawn_mock_upstream("real-upstream-pass").await;
        let (relay2, _, _runtime2, relay_task2) =
            spawn_relay(upstream2, "wrong-upstream-pass").await;
        let socket2 = TcpStream::connect(relay2).await.unwrap();
        let upstream_failure = Socks5Stream::connect_with_password_and_socket(
            socket2,
            echo,
            "relay-user",
            "relay-password",
        )
        .await;
        assert!(upstream_failure.is_err());
        relay_task2.abort();
        upstream_task2.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn no_auth_ingress_forwards_ipv4_connect_and_target_refusal() {
        let (echo, echo_task) = spawn_echo().await;
        let (upstream, address_type, upstream_task) = spawn_mock_upstream("upstream-pass").await;
        let (relay, counter, runtime, relay_task) =
            spawn_relay_with_auth(upstream, "upstream-pass", Socks5InboundAuth::NoAuth).await;

        let socket = TcpStream::connect(relay).await.unwrap();
        let mut tunnel = Socks5Stream::connect_with_socket(socket, echo)
            .await
            .expect("no-auth relay should accept an IPv4 CONNECT");
        assert_eq!(address_type.await.unwrap(), 1);
        tunnel.write_all(b"ipv4").await.unwrap();
        let mut response = [0u8; 4];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ipv4");
        drop(tunnel);
        tokio::task::yield_now().await;
        let entry = counter
            .snapshot()
            .await
            .entries
            .into_iter()
            .find(|entry| entry.rule_id == 42)
            .unwrap();
        assert!(entry.upload >= 4 && entry.download >= 4);

        runtime.cancel_all();
        relay_task.abort();
        upstream_task.abort();
        echo_task.abort();

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_target = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        let (upstream2, _, upstream_task2) = spawn_mock_upstream("upstream-pass").await;
        let (relay2, _, runtime2, relay_task2) =
            spawn_relay_with_auth(upstream2, "upstream-pass", Socks5InboundAuth::NoAuth).await;
        let socket2 = TcpStream::connect(relay2).await.unwrap();
        let refused = Socks5Stream::connect_with_socket(socket2, closed_target).await;
        assert!(
            matches!(refused, Err(tokio_socks::Error::ConnectionRefused)),
            "upstream target refusal must be returned as SOCKS5 reply 0x05"
        );
        runtime2.cancel_all();
        relay_task2.abort();
        upstream_task2.abort();
    }

    #[tokio::test]
    async fn ipv6_connect_is_forwarded_when_loopback_ipv6_is_available() {
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("IPv6 loopback unavailable; skipping IPv6 runtime check: {error}");
                return;
            }
        };
        let target = listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let (upstream, address_type, upstream_task) = spawn_mock_upstream("upstream-pass").await;
        let (relay, _, runtime, relay_task) = spawn_relay(upstream, "upstream-pass").await;

        let socket = TcpStream::connect(relay).await.unwrap();
        let mut tunnel = Socks5Stream::connect_with_password_and_socket(
            socket,
            target,
            "relay-user",
            "relay-password",
        )
        .await
        .expect("IPv6 CONNECT should traverse both SOCKS5 hops");
        assert_eq!(address_type.await.unwrap(), 4);
        tunnel.write_all(b"ipv6").await.unwrap();
        let mut response = [0u8; 4];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ipv6");

        runtime.cancel_all();
        relay_task.abort();
        upstream_task.abort();
        echo_task.abort();
    }
}
