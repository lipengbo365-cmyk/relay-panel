//! Directed, bounded SOCKS5 health checks executed from the Relay Node.

use crate::config::NodeConfig;
use relay_shared::protocol::{
    Socks5CheckRequest, Socks5CheckResult, Socks5CheckStage, Socks5HealthStatus,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

const STAGE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageIoError {
    Timeout,
    Io,
}

trait CheckStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> CheckStream for T {}

pub struct Socks5CheckRuntime {
    semaphore: Arc<Semaphore>,
    waiting: Arc<AtomicUsize>,
    queue_limit: usize,
}

impl Socks5CheckRuntime {
    pub fn new(concurrency: usize, queue_limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency.max(1))),
            waiting: Arc::new(AtomicUsize::new(0)),
            queue_limit: queue_limit.max(1),
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.waiting.load(Ordering::Relaxed)
    }

    fn try_enqueue(&self) -> bool {
        self.waiting
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiting| {
                (waiting < self.queue_limit).then_some(waiting + 1)
            })
            .is_ok()
    }

    pub fn submit(
        self: &Arc<Self>,
        request: Socks5CheckRequest,
        config: NodeConfig,
        local_node_id: String,
    ) {
        if request.node_id != local_node_id {
            tracing::warn!(
                "ignoring SOCKS5 check {} for another node",
                request.request_id
            );
            return;
        }
        if !self.try_enqueue() {
            let result = failure_result(
                &request,
                &local_node_id,
                Socks5HealthStatus::Unknown,
                None,
                "NODE_BUSY",
                "SOCKS5 health-check queue is full",
                Instant::now(),
            );
            tokio::spawn(async move { report(&config, &result).await });
            return;
        }

        let runtime = self.clone();
        tokio::spawn(async move {
            let permit = runtime.semaphore.clone().acquire_owned().await;
            runtime.waiting.fetch_sub(1, Ordering::AcqRel);
            let Ok(_permit) = permit else {
                return;
            };
            let result = execute_check(&request, &local_node_id).await;
            report(&config, &result).await;
        });
    }
}

async fn report(config: &NodeConfig, result: &Socks5CheckResult) {
    let url = format!("{}/api/v1/node/socks5-check-result", config.panel_url);
    let client = reqwest::Client::new();
    for attempt in 0..3 {
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.token))
            .json(result)
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => return,
            Ok(response) if response.status().is_server_error() && attempt < 2 => {}
            Ok(response) => {
                tracing::warn!(
                    "SOCKS5 check {} result rejected: HTTP {}",
                    result.request_id,
                    response.status()
                );
                return;
            }
            Err(_) if attempt < 2 => {}
            Err(error) => {
                tracing::warn!(
                    "SOCKS5 check {} result delivery failed: {}",
                    result.request_id,
                    error
                );
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200 * (attempt + 1) as u64)).await;
    }
}

async fn execute_check(request: &Socks5CheckRequest, node_id: &str) -> Socks5CheckResult {
    let overall = Instant::now();
    if request.check_urls.is_empty() {
        return failure_result(
            request,
            node_id,
            Socks5HealthStatus::Unknown,
            Some(Socks5CheckStage::InternetRequest),
            "NO_CHECK_ENDPOINT",
            "no Internet check endpoint configured",
            overall,
        );
    }

    let mut last = None;
    for endpoint in request.check_urls.iter().take(4) {
        let result = check_endpoint(request, node_id, endpoint, overall).await;
        if result.status == Socks5HealthStatus::Online
            || matches!(
                result.status,
                Socks5HealthStatus::AuthFailed | Socks5HealthStatus::Offline
            )
        {
            return result;
        }
        last = Some(result);
    }
    last.unwrap_or_else(|| {
        failure_result(
            request,
            node_id,
            Socks5HealthStatus::Unknown,
            Some(Socks5CheckStage::InternetRequest),
            "NO_USABLE_ENDPOINT",
            "no usable Internet check endpoint",
            overall,
        )
    })
}

async fn check_endpoint(
    request: &Socks5CheckRequest,
    node_id: &str,
    endpoint: &str,
    overall: Instant,
) -> Socks5CheckResult {
    let url = match reqwest::Url::parse(endpoint) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => url,
        _ => {
            return failure_result(
                request,
                node_id,
                Socks5HealthStatus::Unknown,
                Some(Socks5CheckStage::InternetRequest),
                "INVALID_CHECK_URL",
                "Internet check endpoint is invalid",
                overall,
            )
        }
    };
    let Some(target_host) = url.host_str() else {
        return failure_result(
            request,
            node_id,
            Socks5HealthStatus::Unknown,
            Some(Socks5CheckStage::InternetRequest),
            "INVALID_CHECK_URL",
            "Internet check endpoint has no host",
            overall,
        );
    };
    let target_port = url.port_or_known_default().unwrap_or(80);

    let tcp_started = Instant::now();
    let proxy = format_endpoint(&request.host, request.port);
    let mut stream = match tokio::time::timeout(STAGE_TIMEOUT, TcpStream::connect(proxy)).await {
        Err(_) => {
            return failure_result(
                request,
                node_id,
                Socks5HealthStatus::Timeout,
                Some(Socks5CheckStage::TcpConnect),
                "TCP_TIMEOUT",
                "SOCKS5 TCP connection timed out",
                overall,
            )
        }
        Ok(Err(_)) => {
            return failure_result(
                request,
                node_id,
                Socks5HealthStatus::Offline,
                Some(Socks5CheckStage::TcpConnect),
                "TCP_CONNECT_FAILED",
                "SOCKS5 TCP connection failed",
                overall,
            )
        }
        Ok(Ok(stream)) => stream,
    };
    let tcp_latency = millis(tcp_started.elapsed());
    let _ = stream.set_nodelay(true);

    let handshake_started = Instant::now();
    let method = if request.username.is_some() {
        0x02
    } else {
        0x00
    };
    if let Err(error) = timed_write(&mut stream, &[0x05, 0x01, method]).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Negotiation,
            "NEGOTIATION_IO",
            "SOCKS5 negotiation failed",
            overall,
            Some(tcp_latency),
            None,
            None,
        );
    }
    let mut greeting = [0u8; 2];
    if let Err(error) = timed_read(&mut stream, &mut greeting).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Negotiation,
            "NEGOTIATION_IO",
            "SOCKS5 negotiation failed",
            overall,
            Some(tcp_latency),
            None,
            None,
        );
    }
    if greeting[0] != 0x05 {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Negotiation,
            "INVALID_NEGOTIATION",
            "SOCKS5 server returned an invalid negotiation response",
            overall,
            Some(tcp_latency),
            None,
            None,
        );
    }
    if greeting[1] == 0xff || greeting[1] != method {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::AuthFailed,
            Socks5CheckStage::Authentication,
            "AUTH_METHOD_REJECTED",
            "SOCKS5 authentication method was rejected",
            overall,
            Some(tcp_latency),
            Some(millis(handshake_started.elapsed())),
            None,
        );
    }

    if method == 0x02 {
        let username = request.username.as_deref().unwrap_or("").as_bytes();
        let password = request
            .password
            .as_ref()
            .map(|value| value.expose().as_bytes())
            .unwrap_or_default();
        if username.is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 255
        {
            return timed_failure(
                request,
                node_id,
                Socks5HealthStatus::AuthFailed,
                Socks5CheckStage::Authentication,
                "INVALID_CREDENTIAL_LENGTH",
                "SOCKS5 credentials are empty or too long",
                overall,
                Some(tcp_latency),
                Some(millis(handshake_started.elapsed())),
                None,
            );
        }
        let mut auth = Vec::with_capacity(username.len() + password.len() + 3);
        auth.extend_from_slice(&[0x01, username.len() as u8]);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        let mut reply = [0u8; 2];
        if let Err(error) = timed_write(&mut stream, &auth).await {
            return io_failure(
                request,
                node_id,
                error,
                Socks5HealthStatus::AuthFailed,
                Socks5CheckStage::Authentication,
                "AUTH_IO",
                "SOCKS5 authentication exchange failed",
                overall,
                Some(tcp_latency),
                Some(millis(handshake_started.elapsed())),
                None,
            );
        }
        if let Err(error) = timed_read(&mut stream, &mut reply).await {
            return io_failure(
                request,
                node_id,
                error,
                Socks5HealthStatus::AuthFailed,
                Socks5CheckStage::Authentication,
                "AUTH_IO",
                "SOCKS5 authentication exchange failed",
                overall,
                Some(tcp_latency),
                Some(millis(handshake_started.elapsed())),
                None,
            );
        }
        if reply != [0x01, 0x00] {
            return timed_failure(
                request,
                node_id,
                Socks5HealthStatus::AuthFailed,
                Socks5CheckStage::Authentication,
                "AUTH_FAILED",
                "SOCKS5 username or password was rejected",
                overall,
                Some(tcp_latency),
                Some(millis(handshake_started.elapsed())),
                None,
            );
        }
    }
    let handshake_latency = millis(handshake_started.elapsed());

    let connect_started = Instant::now();
    let connect_request = match build_connect_request(target_host, target_port) {
        Ok(value) => value,
        Err(code) => {
            return timed_failure(
                request,
                node_id,
                Socks5HealthStatus::ConnectFailed,
                Socks5CheckStage::Socks5Connect,
                code,
                "Internet check target cannot be encoded",
                overall,
                Some(tcp_latency),
                Some(handshake_latency),
                None,
            )
        }
    };
    if let Err(error) = timed_write(&mut stream, &connect_request).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Connect,
            "CONNECT_IO",
            "SOCKS5 CONNECT request failed",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            None,
        );
    }
    let mut head = [0u8; 4];
    if let Err(error) = timed_read(&mut stream, &mut head).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Connect,
            "CONNECT_IO",
            "SOCKS5 CONNECT response failed",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            None,
        );
    }
    if head[0] != 0x05 {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Connect,
            "INVALID_CONNECT_REPLY",
            "SOCKS5 CONNECT returned an invalid response",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            None,
        );
    }
    if head[1] != 0x00 {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Connect,
            connect_reply_code(head[1]),
            "SOCKS5 CONNECT was rejected",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            None,
        );
    }
    if let Err(error) = consume_bound_address(&mut stream, head[3]).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::Socks5Connect,
            "TRUNCATED_CONNECT_REPLY",
            "SOCKS5 CONNECT response was truncated",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            None,
        );
    }
    let connect_latency = millis(connect_started.elapsed());

    let mut boxed: Box<dyn CheckStream> = if url.scheme() == "https" {
        match wrap_tls(stream, target_host).await {
            Ok(stream) => Box::new(stream),
            Err(error) => {
                return io_failure(
                    request,
                    node_id,
                    error,
                    Socks5HealthStatus::ConnectFailed,
                    Socks5CheckStage::InternetRequest,
                    "TLS_FAILED",
                    "TLS handshake with Internet check endpoint failed",
                    overall,
                    Some(tcp_latency),
                    Some(handshake_latency),
                    Some(connect_latency),
                )
            }
        }
    } else {
        Box::new(stream)
    };

    let path = if let Some(query) = url.query() {
        format!("{}?{}", url.path(), query)
    } else if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    let request_bytes = format!(
        "GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\nAccept: text/plain\r\nUser-Agent: RelayPanel-Health/1\r\n\r\n"
    );
    if let Err(error) = timed_write(&mut boxed, request_bytes.as_bytes()).await {
        return io_failure(
            request,
            node_id,
            error,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::InternetRequest,
            "HTTP_WRITE_FAILED",
            "Internet check request failed",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            Some(connect_latency),
        );
    }
    let mut response = Vec::new();
    let read = tokio::time::timeout(
        STAGE_TIMEOUT,
        boxed.take(MAX_RESPONSE_BYTES).read_to_end(&mut response),
    )
    .await;
    match read {
        Ok(Ok(_)) => {}
        Err(_) => {
            return timed_failure(
                request,
                node_id,
                Socks5HealthStatus::Timeout,
                Socks5CheckStage::InternetRequest,
                "HTTP_TIMEOUT",
                "Internet check response timed out",
                overall,
                Some(tcp_latency),
                Some(handshake_latency),
                Some(connect_latency),
            )
        }
        Ok(Err(_)) => {
            return timed_failure(
                request,
                node_id,
                Socks5HealthStatus::ConnectFailed,
                Socks5CheckStage::InternetRequest,
                "HTTP_READ_FAILED",
                "Internet check response failed",
                overall,
                Some(tcp_latency),
                Some(handshake_latency),
                Some(connect_latency),
            )
        }
    }
    let Some(split) = response.windows(4).position(|part| part == b"\r\n\r\n") else {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::InternetRequest,
            "INVALID_HTTP_RESPONSE",
            "Internet check returned an invalid HTTP response",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            Some(connect_latency),
        );
    };
    let header = String::from_utf8_lossy(&response[..split]);
    if !header
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 "))
    {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::InternetRequest,
            "HTTP_STATUS",
            "Internet check endpoint returned a non-success status",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            Some(connect_latency),
        );
    }
    let raw_body = &response[split + 4..];
    let decoded_body = if header.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    }) {
        match decode_chunked(raw_body) {
            Some(body) => body,
            None => {
                return timed_failure(
                    request,
                    node_id,
                    Socks5HealthStatus::ConnectFailed,
                    Socks5CheckStage::ExitIpParse,
                    "INVALID_CHUNKED_RESPONSE",
                    "Internet check response body was invalid",
                    overall,
                    Some(tcp_latency),
                    Some(handshake_latency),
                    Some(connect_latency),
                )
            }
        }
    } else {
        raw_body.to_vec()
    };
    let body = String::from_utf8_lossy(&decoded_body);
    let Some(exit_ip) = extract_ip(&body) else {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::ExitIpParse,
            "EXIT_IP_PARSE_FAILED",
            "Internet check response did not contain an IP address",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            Some(connect_latency),
        );
    };
    if request.relay_public_ip.as_deref() == Some(exit_ip.as_str()) {
        return timed_failure(
            request,
            node_id,
            Socks5HealthStatus::ConnectFailed,
            Socks5CheckStage::ExitIpParse,
            "EXIT_IP_MISMATCH",
            "SOCKS5 exit IP equals Relay Node public IP",
            overall,
            Some(tcp_latency),
            Some(handshake_latency),
            Some(connect_latency),
        );
    }

    Socks5CheckResult {
        msg_type: "socks5_check_result".into(),
        request_id: request.request_id.clone(),
        challenge: request.challenge.clone(),
        resource_id: request.resource_id,
        relay_node_id: request.relay_node_id,
        node_id: node_id.to_owned(),
        status: Socks5HealthStatus::Online,
        tcp_latency_ms: Some(tcp_latency),
        handshake_latency_ms: Some(handshake_latency),
        connect_latency_ms: Some(connect_latency),
        total_latency_ms: Some(millis(overall.elapsed())),
        exit_ip: Some(exit_ip),
        detected_country: None,
        error_stage: None,
        error_code: None,
        safe_error_message: None,
        checked_at: chrono_now(),
    }
}

async fn wrap_tls(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, StageIoError> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| StageIoError::Io)?;
    tokio::time::timeout(
        STAGE_TIMEOUT,
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream),
    )
    .await
    .map_err(|_| StageIoError::Timeout)?
    .map_err(|_| StageIoError::Io)
}

async fn timed_write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), StageIoError> {
    tokio::time::timeout(STAGE_TIMEOUT, writer.write_all(data))
        .await
        .map_err(|_| StageIoError::Timeout)?
        .map_err(|_| StageIoError::Io)
}
async fn timed_read<R: AsyncRead + Unpin>(
    reader: &mut R,
    data: &mut [u8],
) -> Result<(), StageIoError> {
    tokio::time::timeout(STAGE_TIMEOUT, reader.read_exact(data))
        .await
        .map_err(|_| StageIoError::Timeout)?
        .map(|_| ())
        .map_err(|_| StageIoError::Io)
}
async fn consume_bound_address(stream: &mut TcpStream, atyp: u8) -> Result<(), StageIoError> {
    let length = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            timed_read(stream, &mut len).await?;
            usize::from(len[0])
        }
        _ => return Err(StageIoError::Io),
    };
    let mut rest = vec![0u8; length + 2];
    timed_read(stream, &mut rest).await
}
fn build_connect_request(host: &str, port: u16) -> Result<Vec<u8>, &'static str> {
    let mut out = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v) => {
                out.push(0x01);
                out.extend_from_slice(&v.octets())
            }
            IpAddr::V6(v) => {
                out.push(0x04);
                out.extend_from_slice(&v.octets())
            }
        }
    } else {
        if host.len() > 255 {
            return Err("TARGET_HOST_TOO_LONG");
        };
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}
fn connect_reply_code(code: u8) -> &'static str {
    match code {
        1 => "SOCKS_GENERAL_FAILURE",
        2 => "SOCKS_NOT_ALLOWED",
        3 => "SOCKS_NETWORK_UNREACHABLE",
        4 => "SOCKS_HOST_UNREACHABLE",
        5 => "SOCKS_CONNECTION_REFUSED",
        6 => "SOCKS_TTL_EXPIRED",
        7 => "SOCKS_COMMAND_UNSUPPORTED",
        8 => "SOCKS_ADDRESS_UNSUPPORTED",
        _ => "SOCKS_CONNECT_REJECTED",
    }
}
fn extract_ip(body: &str) -> Option<String> {
    body.split(|c: char| c.is_whitespace() || matches!(c, ',' | '"' | '\'' | '[' | ']'))
        .map(|v| v.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':'))
        .find_map(|v| v.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
}
fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..].windows(2).position(|part| part == b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        cursor = line_end + 2;
        if size == 0 {
            return Some(decoded);
        }
        let data_end = cursor.checked_add(size)?;
        if data_end + 2 > body.len() || &body[data_end..data_end + 2] != b"\r\n" {
            return None;
        }
        decoded.extend_from_slice(&body[cursor..data_end]);
        cursor = data_end + 2;
    }
}
fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn millis(value: Duration) -> u64 {
    value.as_millis().min(u128::from(u64::MAX)) as u64
}
fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[allow(clippy::too_many_arguments)]
fn timed_failure(
    request: &Socks5CheckRequest,
    node_id: &str,
    status: Socks5HealthStatus,
    stage: Socks5CheckStage,
    code: &str,
    message: &str,
    overall: Instant,
    tcp: Option<u64>,
    handshake: Option<u64>,
    connect: Option<u64>,
) -> Socks5CheckResult {
    let mut result = failure_result(
        request,
        node_id,
        status,
        Some(stage),
        code,
        message,
        overall,
    );
    result.tcp_latency_ms = tcp;
    result.handshake_latency_ms = handshake;
    result.connect_latency_ms = connect;
    result
}

#[allow(clippy::too_many_arguments)]
fn io_failure(
    request: &Socks5CheckRequest,
    node_id: &str,
    error: StageIoError,
    fallback_status: Socks5HealthStatus,
    stage: Socks5CheckStage,
    fallback_code: &str,
    fallback_message: &str,
    overall: Instant,
    tcp: Option<u64>,
    handshake: Option<u64>,
    connect: Option<u64>,
) -> Socks5CheckResult {
    let (status, code, message) = match error {
        StageIoError::Timeout => (
            Socks5HealthStatus::Timeout,
            "STAGE_TIMEOUT",
            "SOCKS5 health-check stage timed out",
        ),
        StageIoError::Io => (fallback_status, fallback_code, fallback_message),
    };
    timed_failure(
        request, node_id, status, stage, code, message, overall, tcp, handshake, connect,
    )
}
fn failure_result(
    request: &Socks5CheckRequest,
    node_id: &str,
    status: Socks5HealthStatus,
    stage: Option<Socks5CheckStage>,
    code: &str,
    message: &str,
    overall: Instant,
) -> Socks5CheckResult {
    Socks5CheckResult {
        msg_type: "socks5_check_result".into(),
        request_id: request.request_id.clone(),
        challenge: request.challenge.clone(),
        resource_id: request.resource_id,
        relay_node_id: request.relay_node_id,
        node_id: node_id.to_owned(),
        status,
        tcp_latency_ms: None,
        handshake_latency_ms: None,
        connect_latency_ms: None,
        total_latency_ms: Some(millis(overall.elapsed())),
        exit_ip: None,
        detected_country: None,
        error_stage: stage,
        error_code: Some(code.into()),
        safe_error_message: Some(message.into()),
        checked_at: chrono_now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[derive(Clone, Copy)]
    enum MockMode {
        Online,
        AuthFailed,
        ConnectFailed,
        Timeout,
    }

    async fn mock_proxy(mode: MockMode) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            if matches!(mode, MockMode::Timeout) {
                tokio::time::sleep(STAGE_TIMEOUT + Duration::from_secs(1)).await;
                return;
            }
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth_head = [0u8; 2];
            stream.read_exact(&mut auth_head).await.unwrap();
            let mut username = vec![0u8; usize::from(auth_head[1])];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_len = [0u8; 1];
            stream.read_exact(&mut password_len).await.unwrap();
            let mut password = vec![0u8; usize::from(password_len[0])];
            stream.read_exact(&mut password).await.unwrap();
            if matches!(mode, MockMode::AuthFailed) {
                stream.write_all(&[0x01, 0x01]).await.unwrap();
                return;
            }
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut connect_head = [0u8; 4];
            stream.read_exact(&mut connect_head).await.unwrap();
            let address_len = match connect_head[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut length = [0u8; 1];
                    stream.read_exact(&mut length).await.unwrap();
                    usize::from(length[0])
                }
                _ => return,
            };
            let mut target = vec![0u8; address_len + 2];
            stream.read_exact(&mut target).await.unwrap();
            if matches!(mode, MockMode::ConnectFailed) {
                stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                return;
            }
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();

            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n198.51.100.8")
                .await
                .unwrap();
        });
        (port, task)
    }

    fn request(port: u16, relay_public_ip: Option<&str>) -> Socks5CheckRequest {
        Socks5CheckRequest {
            msg_type: "socks5_check".into(),
            request_id: "request-1".into(),
            challenge: "challenge-1".into(),
            resource_id: 7,
            relay_node_id: 9,
            node_id: "node-a".into(),
            host: "127.0.0.1".into(),
            port,
            username: Some("user".into()),
            password: Some(relay_shared::protocol::SecretString::new("password")),
            check_urls: vec!["http://example.com/ip".into()],
            relay_public_ip: relay_public_ip.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn directed_check_classifies_online_auth_and_connect_failure() {
        for (mode, expected) in [
            (MockMode::Online, Socks5HealthStatus::Online),
            (MockMode::AuthFailed, Socks5HealthStatus::AuthFailed),
            (MockMode::ConnectFailed, Socks5HealthStatus::ConnectFailed),
        ] {
            let (port, task) = mock_proxy(mode).await;
            let result = check_endpoint(
                &request(port, None),
                "node-a",
                "http://example.com/ip",
                Instant::now(),
            )
            .await;
            assert_eq!(result.status, expected);
            if matches!(mode, MockMode::Online) {
                assert_eq!(result.exit_ip.as_deref(), Some("198.51.100.8"));
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn directed_check_classifies_timeout_and_exit_mismatch() {
        let (port, timeout_task) = mock_proxy(MockMode::Timeout).await;
        let timed_out = check_endpoint(
            &request(port, None),
            "node-a",
            "http://example.com/ip",
            Instant::now(),
        )
        .await;
        assert_eq!(timed_out.status, Socks5HealthStatus::Timeout);
        assert_eq!(
            timed_out.error_stage,
            Some(Socks5CheckStage::Socks5Negotiation)
        );
        timeout_task.abort();

        let (port, task) = mock_proxy(MockMode::Online).await;
        let mismatch = check_endpoint(
            &request(port, Some("198.51.100.8")),
            "node-a",
            "http://example.com/ip",
            Instant::now(),
        )
        .await;
        assert_eq!(mismatch.status, Socks5HealthStatus::ConnectFailed);
        assert_eq!(mismatch.error_code.as_deref(), Some("EXIT_IP_MISMATCH"));
        task.await.unwrap();
    }

    #[test]
    fn parses_ipv4_and_ipv6_exit_values() {
        assert_eq!(extract_ip("1.2.3.4\n").as_deref(), Some("1.2.3.4"));
        assert_eq!(extract_ip("2001:db8::1").as_deref(), Some("2001:db8::1"));
    }
    #[test]
    fn connect_request_supports_domain_and_ip_families() {
        assert_eq!(build_connect_request("example.com", 80).unwrap()[3], 3);
        assert_eq!(build_connect_request("127.0.0.1", 80).unwrap()[3], 1);
        assert_eq!(build_connect_request("::1", 80).unwrap()[3], 4);
    }
    #[test]
    fn decodes_chunked_exit_ip_body() {
        assert_eq!(
            decode_chunked(b"7\r\n1.2.3.4\r\n1\r\n\n\r\n0\r\n\r\n").as_deref(),
            Some(b"1.2.3.4\n".as_slice())
        );
        assert!(decode_chunked(b"10\r\nshort\r\n").is_none());
    }
    #[test]
    fn queue_is_bounded() {
        let runtime = Socks5CheckRuntime::new(2, 7);
        assert_eq!(runtime.queue_limit, 7);
        assert_eq!(runtime.queue_depth(), 0);
        for _ in 0..7 {
            assert!(runtime.try_enqueue());
        }
        assert!(
            !runtime.try_enqueue(),
            "the eighth task must become NODE_BUSY"
        );
        assert_eq!(runtime.queue_depth(), 7);
    }
}
