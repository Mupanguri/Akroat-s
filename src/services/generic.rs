use crate::services::banner_grabber::grab_banner_with_retries;
use crate::ServiceInfo;

/// Generic service detection for unspecified services
pub fn detect_generic_service(ip: &str, port: u16, hint: &str, deep: bool) -> Option<ServiceInfo> {
    // Try to grab a banner
    if let Some(banner) = grab_banner_with_retries(ip, port, 3000, 2) {
        if banner.is_empty() {
            return None;
        }
        
        // Try to identify service from banner
        let banner_lower = banner.to_lowercase();
        
        // Check for common service indicators in banner
        if banner_lower.contains("ssh") {
            return Some(ServiceInfo {
                name: "SSH".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("ftp") {
            return Some(crate::services::ServiceInfo {
                name: "FTP".to_string(),
                version: extract_version_from_banner(&banner),
                product: None,
                extrainfo: Some(banner),
                cpe: None,
            });
        } else if banner_lower.contains("http") || banner_lower.contains("html") {
            // Try HTTP-specific detection
            if let Some(info) = crate::services::http::detect_http(ip, port, deep) {
                return Some(info);
            }
            // Fallback to generic HTTP
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
            // Generic service with banner
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
    
    // If we couldn't get a banner but know the port is common, return basic info
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

/// Extract version information from a banner string
fn extract_version_from_banner(banner: &str) -> Option<String> {
    // Common version patterns
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