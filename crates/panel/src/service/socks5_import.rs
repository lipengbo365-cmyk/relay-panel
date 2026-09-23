//! Server-side parser for SOCKS5 bulk imports.
//!
//! Passwords deliberately exist only in [`ParsedImportLine`], which is an
//! internal service type and does not implement `Serialize` or `Debug`.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone)]
pub struct ParsedImportLine {
    pub line_number: usize,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ParsedImportLine {
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}\u{0}{}\u{0}{}",
            self.host,
            self.port,
            self.username.as_deref().unwrap_or("")
        )
    }

    pub fn generated_name(&self) -> String {
        format!("{}:{}", display_host(&self.host), self.port)
    }
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct ImportLineError {
    pub line_number: usize,
    pub error_code: &'static str,
    pub raw_masked: String,
    pub error_reason: String,
}

#[derive(Default)]
pub struct ParsedImport {
    pub total: usize,
    pub valid: Vec<ParsedImportLine>,
    pub invalid: Vec<ImportLineError>,
    /// Duplicate line number -> first occurrence line number.
    pub duplicates: Vec<(usize, usize)>,
}

pub fn parse_import(input: &str, max_lines: usize) -> ParsedImport {
    let mut result = ParsedImport::default();
    let mut seen = HashMap::<String, usize>::new();

    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        result.total += 1;
        if result.total > max_lines {
            result.invalid.push(ImportLineError {
                line_number,
                error_code: "LIMIT_EXCEEDED",
                raw_masked: mask_raw(raw),
                error_reason: format!("导入最多允许 {max_lines} 条非空记录"),
            });
            // One sentinel is sufficient to reject the request. Continuing
            // over millions of tiny lines would amplify a bounded HTTP body
            // into an unbounded validation-error vector and response.
            break;
        }

        match parse_line(line_number, raw) {
            Ok(line) => {
                let key = line.dedupe_key();
                if let Some(first) = seen.get(&key) {
                    result.duplicates.push((line_number, *first));
                } else {
                    seen.insert(key, line_number);
                    result.valid.push(line);
                }
            }
            Err(reason) => result.invalid.push(ImportLineError {
                line_number,
                error_code: "INVALID_FORMAT",
                raw_masked: mask_raw(raw),
                error_reason: reason,
            }),
        }
    }
    result
}

fn parse_line(line_number: usize, raw: &str) -> Result<ParsedImportLine, String> {
    let (without_scheme, uri_form) = if let Some(rest) = raw.strip_prefix("socks5://") {
        (rest, true)
    } else if raw.contains("://") {
        return Err("仅支持 socks5:// scheme".into());
    } else {
        (raw, false)
    };

    let (username, password, endpoint) = if !uri_form {
        if let Some((endpoint, username, password)) = split_host_form(without_scheme) {
            (
                username.map(normalize_credential).transpose()?.flatten(),
                password.map(ToOwned::to_owned),
                endpoint,
            )
        } else if let Some((auth, endpoint)) = without_scheme.rsplit_once('@') {
            let (username, password) = auth
                .split_once(':')
                .ok_or_else(|| "认证部分必须是 user:password".to_string())?;
            (
                normalize_credential(username)?,
                Some(password.to_owned()),
                endpoint,
            )
        } else {
            (None, None, without_scheme)
        }
    } else if let Some((auth, endpoint)) = without_scheme.rsplit_once('@') {
        let (username, password) = auth
            .split_once(':')
            .ok_or_else(|| "认证部分必须是 user:password".to_string())?;
        (
            normalize_credential(username)?,
            Some(password.to_owned()),
            endpoint,
        )
    } else {
        (None, None, without_scheme)
    };

    if username.is_some() != password.is_some() {
        return Err("用户名和密码必须同时提供".into());
    }
    if password.as_deref().is_some_and(str::is_empty) {
        return Err("密码不能为空".into());
    }
    if password.as_deref().is_some_and(|value| value.len() > 255) {
        return Err("密码不能超过 255 字节".into());
    }
    let (host, port) = parse_endpoint(endpoint)?;
    Ok(ParsedImportLine {
        line_number,
        host,
        port,
        username,
        password,
    })
}

/// Recognize the unambiguous legacy endpoint-first forms. Looking for a
/// numeric port before considering `@` is what allows `@` inside the password
/// of `host:port:user:password` without breaking `user:password@host:port`.
fn split_host_form(value: &str) -> Option<(&str, Option<&str>, Option<&str>)> {
    if value.starts_with('[') {
        let close = value.find(']')?;
        let suffix = value.get(close + 1..)?.strip_prefix(':')?;
        let mut fields = suffix.splitn(3, ':');
        let port = fields.next()?;
        port.parse::<u16>().ok()?;
        let endpoint_end = close + 2 + port.len();
        return match (fields.next(), fields.next()) {
            (None, None) => Some((&value[..endpoint_end], None, None)),
            (Some(user), Some(password)) => {
                Some((&value[..endpoint_end], Some(user), Some(password)))
            }
            _ => None,
        };
    }
    let mut fields = value.splitn(4, ':');
    let host = fields.next()?;
    let port = fields.next()?;
    port.parse::<u16>().ok()?;
    let endpoint_end = host.len() + 1 + port.len();
    match (fields.next(), fields.next()) {
        (None, None) => Some((&value[..endpoint_end], None, None)),
        (Some(user), Some(password)) => Some((&value[..endpoint_end], Some(user), Some(password))),
        _ => None,
    }
}

fn normalize_credential(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        Err("用户名不能为空".into())
    } else if value.len() > 255 {
        Err("用户名不能超过 255 字节".into())
    } else {
        Ok(Some(value.to_owned()))
    }
}

fn parse_endpoint(value: &str) -> Result<(String, i32), String> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "IPv6 地址缺少 ]".to_string())?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| "IPv6 地址后缺少端口".to_string())?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .ok_or_else(|| "缺少 host:port".to_string())?
    };
    let host = normalize_host(host)?;
    let port: i32 = port.parse().map_err(|_| "端口不是有效整数".to_string())?;
    if !(1..=65535).contains(&port) {
        return Err("端口必须在 1..65535".into());
    }
    Ok((host, port))
}

pub fn normalize_host(host: &str) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return Err("host 为空或过长".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if host.contains(':')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("host 不是有效的 IP 或域名".into());
    }
    Ok(host.to_ascii_lowercase())
}

pub fn mask_raw(raw: &str) -> String {
    let _ = raw;
    // Invalid syntax is inherently ambiguous: a colon-delimited IPv6 suffix,
    // malformed URI, or duplicate separator may place a password anywhere.
    // Returning any substring risks disclosing it, so validation responses
    // expose only the line number and this irreversible placeholder.
    "***".to_owned()
}

fn display_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_formats_and_normalizes() {
        let parsed = parse_import(
            "EXAMPLE.COM.:1080\n1.2.3.4:9000:u:p\nu:p@proxy.test:1081\nsocks5://u:p@[2001:db8::1]:1080",
            100,
        );
        assert_eq!(parsed.total, 4);
        assert!(parsed.invalid.is_empty());
        assert_eq!(parsed.valid[0].host, "example.com");
        assert_eq!(parsed.valid[1].username.as_deref(), Some("u"));
        assert_eq!(parsed.valid[2].password.as_deref(), Some("p"));
        assert_eq!(parsed.valid[3].host, "2001:db8::1");
    }

    #[test]
    fn preview_errors_never_echo_passwords() {
        let secret = "do-not-return-this";
        let parsed = parse_import(&format!("socks5://user:{secret}@bad host:1080"), 10);
        assert_eq!(parsed.invalid.len(), 1);
        let json = serde_json::to_string(&parsed.invalid).unwrap();
        assert!(!json.contains(secret));
        assert!(json.contains("***"));
    }

    #[test]
    fn deduplicates_normalized_endpoint_and_username() {
        let parsed = parse_import("Example.com:1080:u:a\nexample.com.:1080:u:b", 10);
        assert_eq!(parsed.valid.len(), 1);
        assert_eq!(parsed.duplicates, vec![(2, 1)]);
    }

    #[test]
    fn rejects_invalid_and_over_limit_rows_independently() {
        let input = "ok.test:1080\nbad\nalso.test:70000\nlast.test:1080";
        let parsed = parse_import(input, 10);
        assert_eq!(parsed.total, 4);
        assert_eq!(parsed.valid.len(), 2);
        assert_eq!(parsed.invalid.len(), 2);

        let over_limit = parse_import(input, 2);
        assert_eq!(over_limit.total, 3);
        assert_eq!(over_limit.valid.len(), 1);
        assert_eq!(over_limit.invalid.len(), 2);
        assert_eq!(
            over_limit
                .invalid
                .iter()
                .filter(|error| error.error_reason.contains("最多允许"))
                .count(),
            1
        );
    }

    #[test]
    fn parses_ipv4_ipv6_domain_crlf_unicode_and_reserved_password_chars() {
        let parsed = parse_import(
            "  192.0.2.1:1080  \r\n[2001:db8::1]:1080\r\nproxy.example:1080:用户:p:a@/\\#?%\r\nsocks5://user:p:a@/\\#?%25@host.example:1080\r\n",
            100,
        );
        assert_eq!(parsed.total, 4);
        assert!(parsed.invalid.is_empty(), "unexpected parse failure");
        assert_eq!(parsed.valid[1].host, "2001:db8::1");
        assert_eq!(parsed.valid[2].password.as_deref(), Some("p:a@/\\#?%"));
        assert_eq!(parsed.valid[3].password.as_deref(), Some("p:a@/\\#?%25"));
    }

    #[test]
    fn percent_encoding_is_preserved_without_ambiguous_decode() {
        let parsed = parse_import("socks5://u%40name:p%3Aword@host.example:1080", 10);
        assert!(parsed.invalid.is_empty());
        assert_eq!(parsed.valid[0].username.as_deref(), Some("u%40name"));
        assert_eq!(parsed.valid[0].password.as_deref(), Some("p%3Aword"));
    }

    #[test]
    fn malformed_uri_and_oversized_rows_never_echo_secret_or_unbounded_input() {
        let secret = "malformed-secret";
        let parsed = parse_import(&format!("socks5://user:{secret}"), 10);
        assert_eq!(parsed.invalid.len(), 1);
        assert!(!parsed.invalid[0].raw_masked.contains(secret));

        let huge = "x".repeat(10_000);
        let parsed = parse_import(&huge, 10);
        assert_eq!(parsed.invalid[0].raw_masked, "***");
    }

    #[test]
    fn malformed_bracketed_rows_never_echo_credentials() {
        let secret = "ipv6-secret";
        let parsed = parse_import(&format!("[2001:db8::1]:bad:user:{secret}"), 10);
        assert_eq!(parsed.invalid.len(), 1);
        assert_eq!(parsed.invalid[0].raw_masked, "***");
        assert!(!serde_json::to_string(&parsed.invalid)
            .unwrap()
            .contains(secret));
    }

    #[test]
    fn excessive_tiny_lines_create_only_one_bounded_error() {
        let input = "x\n".repeat(50_000);
        let parsed = parse_import(&input, 10_000);
        assert_eq!(parsed.total, 10_001);
        assert_eq!(parsed.invalid.len(), 10_001);
        assert_eq!(
            parsed
                .invalid
                .iter()
                .filter(|error| error.error_reason.contains("最多允许"))
                .count(),
            1
        );
    }

    #[test]
    fn parser_edge_cases_preserve_accounting() {
        let parsed = parse_import(
            "\n\t\n host.example:1080 \ninvalid\nhost.example:1080\n[2001:db8::1]:1080\n",
            10,
        );
        assert_eq!(parsed.total, 4);
        assert_eq!(parsed.valid.len(), 2);
        assert_eq!(parsed.duplicates.len(), 1);
        assert_eq!(parsed.invalid.len(), 1);
        assert_eq!(
            parsed.valid.len() + parsed.duplicates.len() + parsed.invalid.len(),
            parsed.total
        );
    }

    #[test]
    fn invalid_rows_at_chunk_boundaries_preserve_accounting() {
        for invalid_line in [499usize, 500, 501] {
            let input = (1..=1_000)
                .map(|line| {
                    if line == invalid_line {
                        "socks5://user:secret@bad host:1080".to_owned()
                    } else {
                        format!("proxy-{line}.example:1080")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let parsed = parse_import(&input, 10_000);
            assert_eq!(parsed.total, 1_000);
            assert_eq!(parsed.valid.len(), 999);
            assert_eq!(parsed.invalid.len(), 1);
            assert_eq!(parsed.invalid[0].line_number, invalid_line);
            assert_eq!(parsed.invalid[0].error_code, "INVALID_FORMAT");
            assert_eq!(parsed.invalid[0].raw_masked, "***");
        }
    }

    #[test]
    fn sixteen_mibibytes_of_invalid_tiny_lines_stops_at_fixed_limit() {
        let input = "x\n".repeat(8 * 1024 * 1024);
        let parsed = parse_import(&input, 10_000);
        assert_eq!(parsed.total, 10_001);
        assert_eq!(parsed.invalid.len(), 10_001);
        assert_eq!(parsed.invalid.last().unwrap().error_code, "LIMIT_EXCEEDED");
    }

    #[test]
    fn password_space_and_unicode_are_preserved_without_echo_on_failure() {
        let parsed = parse_import(
            "proxy.example:1080:user:密 码 with spaces\nsocks5://用户:密 码@proxy2.example:1080",
            10,
        );
        assert!(parsed.invalid.is_empty());
        assert_eq!(
            parsed.valid[0].password.as_deref(),
            Some("密 码 with spaces")
        );
        assert_eq!(parsed.valid[1].password.as_deref(), Some("密 码"));
    }
}
