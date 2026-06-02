use crate::services::banner_grabber::grab_banner_with_retries;
use crate::ServiceInfo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Detect SMB service and extract version information
pub async fn detect_smb(ip: &str, port: u16) -> Option<ServiceInfo> {
    if port != 445 && port != 139 && port != 137 {
        return None;
    }

    if let Some(banner) = grab_banner_with_retries(ip, port, 5000, 1).await {
        if !banner.is_empty() {
            let banner_upper = banner.to_uppercase();
            if banner_upper.contains("SMB")
                || banner_upper.contains("CIFS")
                || banner_upper.contains("MICROSOFT")
                || banner_upper.contains("WINDOWS")
            {
                let version = extract_smb_version(&banner);
                let product = extract_smb_product(&banner);
                return Some(ServiceInfo {
                    name: "SMB".to_string(),
                    version,
                    product,
                    extrainfo: Some(banner),
                    cpe: None,
                });
            }
        }
    }

    Some(ServiceInfo {
        name: "SMB".to_string(),
        version: None,
        product: None,
        extrainfo: None,
        cpe: None,
    })
}

fn build_smb_negotiate_request() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x00\x00\x00\x90");
    buf.extend_from_slice(b"\xff\x53\x4d\x42");
    buf.extend_from_slice(b"\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    buf.extend_from_slice(b"\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    buf.extend_from_slice(b"\x02\x00\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    buf.extend_from_slice(b"\x02\x10\x02\x02\x03\x02\x00\x00\x00\x00\x00\x00\x00\x00");
    buf
}

fn parse_smb_negotiate_response(response: &[u8]) -> Option<String> {
    if response.len() < 80 {
        return None;
    }

    if response[4..8] == [0xfe, 0x53, 0x4d, 0x42] {
        let _status = u32::from_le_bytes(response[8..12].try_into().ok()?);
        if _status != 0 {
            return None;
        }

        let dialect_revision = u16::from_le_bytes(response[72..74].try_into().ok()?);
        let security_mode = response[74];
        let _capabilities = u32::from_le_bytes(response[100..104].try_into().ok()?);
        let max_transact_size = u32::from_le_bytes(response[104..108].try_into().ok()?);

        let os_info = match dialect_revision {
            0x0202 => "Windows 8/Server 2012".to_string(),
            0x0210 => "Windows 8.1/Server 2012 R2".to_string(),
            0x0300 => "Windows 10/Server 2016".to_string(),
            0x0302 => "Windows 10/11/Server 2022".to_string(),
            _ => format!("SMBv2 dialect {:#x}", dialect_revision),
        };

        return Some(format!(
            "{} | MaxTransact: {} | SecMode: {:#x} | GUID: {}",
            os_info,
            max_transact_size,
            security_mode,
            hex_encode(&response[80..88])
        ));
    }

    if response[4..8] == [0xff, 0x53, 0x4d, 0x42] {
        let word_count = response[36] as usize;
        if word_count > 0 && response.len() > 37 + word_count * 2 {
            return Some("SMBv1 protocol".to_string());
        }
    }

    None
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Enumerate SMB shares using raw SMB protocol negotiation
pub async fn enumerate_smb_shares(ip: &str, port: u16) -> Option<Vec<String>> {
    let addr = format!("{}:{}", ip, port);
    let dur = Duration::from_secs(5);

    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let request = build_smb_negotiate_request();
            if timeout(dur, stream.write_all(&request)).await.is_err() {
                return None;
            }

            let mut buf = vec![0u8; 2048];
            match timeout(dur, stream.read(&mut buf)).await {
                Ok(Ok(size)) if size > 0 => {
                    if let Some(os_info) = parse_smb_negotiate_response(&buf[..size]) {
                        let mut shares = vec![os_info];
                        if let Some(share_names) = extract_share_hints(&buf[..size]) {
                            shares.extend(share_names);
                        }
                        Some(shares)
                    } else {
                        Some(vec!["SMB detected (negotiate response unparseable)".to_string()])
                    }
                }
                _ => Some(vec!["SMB detected (no negotiate response)".to_string()]),
            }
        }
        _ => None,
    }
}

fn extract_share_hints(response: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(response);
    let lower = text.to_lowercase();

    let mut hints = Vec::new();
    if lower.contains("windows") {
        hints.push("Windows SMB server".to_string());
    }
    if lower.contains("samba") {
        hints.push("Samba".to_string());
    }
    if lower.contains("netapp") {
        hints.push("NetApp".to_string());
    }

    if hints.is_empty() {
        None
    } else {
        Some(hints)
    }
}

fn extract_smb_version(banner: &str) -> Option<String> {
    let patterns = [
        regex::Regex::new(r"Windows\s+([^\s,]+)").ok()?,
        regex::Regex::new(r"Samba\s+([^\s,]+)").ok()?,
        regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"(\d+\.\d+)").ok()?,
    ];

    for pattern in patterns {
        if let Some(cap) = pattern.captures(banner) {
            if let Some(m) = cap.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }

    None
}

fn extract_smb_product(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();

    if banner_lower.contains("windows") {
        Some("Microsoft Windows SMB".to_string())
    } else if banner_lower.contains("samba") {
        Some("Samba".to_string())
    } else if banner_lower.contains("netapp") {
        Some("NetApp SMB".to_string())
    } else if banner_lower.contains("cifs") {
        Some("CIFS".to_string())
    } else {
        None
    }
}
