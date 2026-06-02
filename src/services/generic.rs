use crate::services::banner_grabber::grab_banner_with_retries;
use crate::ServiceInfo;

/// Generic service detection for unspecified services
pub async fn detect_generic_service(
    ip: &str,
    port: u16,
    hint: &str,
    deep: bool,
) -> Option<ServiceInfo> {
    if let Some(banner) = grab_banner_with_retries(ip, port, 3000, 2).await {
        if banner.is_empty() {
            return None;
        }

        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("ssh") {
            return Some(ServiceInfo {
                name: "SSH".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("ftp") {
            return Some(ServiceInfo {
                name: "FTP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("http") || banner_lower.contains("html") {
            if let Some(info) = crate::services::http::detect_http(ip, port, deep).await {
                return Some(info);
            }
            return Some(ServiceInfo {
                name: "HTTP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("smtp") {
            return Some(ServiceInfo {
                name: "SMTP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("imap") {
            return Some(ServiceInfo {
                name: "IMAP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("pop3") {
            return Some(ServiceInfo {
                name: "POP3".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("telnet") {
            return Some(ServiceInfo {
                name: "Telnet".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("mysql") {
            return Some(ServiceInfo {
                name: "MySQL".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("postgres") {
            return Some(ServiceInfo {
                name: "PostgreSQL".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("microsoft") || banner_lower.contains("msftp") {
            return Some(ServiceInfo {
                name: "Microsoft FTP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else {
            return Some(ServiceInfo {
                name: if !hint.is_empty() {
                    hint.to_string().to_uppercase()
                } else {
                    "Unknown".to_string()
                },
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        }
    }

    if !hint.is_empty() {
        return Some(ServiceInfo {
            name: hint.to_string().to_uppercase(),
            version: None,
            product: None,
            extrainfo: None,
            cpe: None,
        });
    }

    None
}

fn extract_version_from_banner(banner: &str) -> Option<String> {
    let patterns = [
        regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"(\d+\.\d+)").ok()?,
        regex::Regex::new(r"v(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"version[:\s]+(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"Version[:\s]+(\d+\.\d+\.\d+)").ok()?,
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
