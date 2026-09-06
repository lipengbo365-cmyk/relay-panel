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
                raw_masked: mask_raw(raw),
                error_reason: format!("导入最多允许 {max_lines} 条非空记录"),
            });
            continue;
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
                raw_masked: mask_raw(raw),
                error_reason: reason,
            }),
        }
    }
    result
}

fn parse_line(line_number: usize, raw: &str) -> Result<ParsedImportLine, String> {
    let without_scheme = if let Some(rest) = raw.strip_prefix("socks5://") {
        rest
    } else if raw.contains("://") {
        return Err("仅支持 socks5:// scheme".into());
    } else {
        raw
    };

    let (username, password, endpoint) =
        if let Some((auth, endpoint)) = without_scheme.rsplit_once('@') {
            let (username, password) = auth
                .split_once(':')
                .ok_or_else(|| "认证部分必须是 user:password".to_string())?;
            (
                normalize_credential(username)?,
                Some(password.to_owned()),
                endpoint,
            )
        } else if !without_scheme.starts_with('[') {
            let mut parts = without_scheme.splitn(4, ':');
            let host = parts.next().unwrap_or_default();
            let port = parts.next().ok_or_else(|| "缺少端口".to_string())?;
            match (parts.next(), parts.next()) {
                (None, None) => (None, None, without_scheme),
                (Some(user), Some(password)) => {
                    let endpoint_len = host.len() + 1 + port.len();
                    (
                        normalize_credential(user)?,
                        Some(password.to_owned()),
                        &without_scheme[..endpoint_len],
                    )
                }
                _ => return Err("格式应为 host:port:user:password".into()),
            }
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
    let raw = raw.trim();
    if let Some((left, _)) = raw.rsplit_once('@') {
        let scheme = if raw.starts_with("socks5://") {
            "socks5://"
        } else {
            ""
        };
        let auth = left.strip_prefix(scheme).unwrap_or(left);
        let user = auth.split_once(':').map(|v| v.0).unwrap_or("***");
        let endpoint = raw.rsplit_once('@').map(|v| v.1).unwrap_or("");
        return format!("{scheme}{user}:***@{endpoint}");
    }
    if !raw.starts_with('[') {
        let parts: Vec<&str> = raw.splitn(4, ':').collect();
        if parts.len() == 4 {
            return format!("{}:{}:{}:***", parts[0], parts[1], parts[2]);
        }
    }
    raw.to_owned()
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
        let parsed = parse_import("ok.test:1080\nbad\nalso.test:70000\nlast.test:1080", 2);
        assert_eq!(parsed.total, 4);
        assert_eq!(parsed.valid.len(), 1);
        assert_eq!(parsed.invalid.len(), 3);
    }
}
