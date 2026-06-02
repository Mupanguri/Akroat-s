use crate::services::banner_grabber::grab_banner_with_retries;
use regex::Regex;
use crate::ServiceInfo;

/// Detect SSH service and extract version information
pub async fn detect_ssh(ip: &str, port: u16) -> Option<ServiceInfo> {
    if let Some(banner) = grab_banner_with_retries(ip, port, 3000, 1).await {
        if banner.starts_with("SSH-") {
            let version = extract_ssh_version(&banner);
            let product = extract_ssh_product(&banner);
            return Some(ServiceInfo {
                name: "SSH".to_string(),
                version,
                product,
                extrainfo: Some(banner),
                cpe: None,
            });
        }
    }
    None
}

pub(crate) fn extract_ssh_version(banner: &str) -> Option<String> {
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() >= 3 {
        let version_part = parts[2..].join("-");
        let re = Regex::new(r"[\d\.]+(?:p\d+)?").ok()?;
        re.find(&version_part).map(|m| m.as_str().to_string())
    } else {
        None
    }
}

pub(crate) fn extract_ssh_product(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("openssh") {
        Some("OpenSSH".to_string())
    } else if banner_lower.contains("dropbear") {
        Some("Dropbear".to_string())
    } else if banner_lower.contains("libssh") {
        Some("libssh".to_string())
    } else if banner_lower.contains("ssh.com") || banner_lower.contains("ssh communications") {
        Some("SSH Communications Security".to_string())
    } else if banner_lower.contains("weonlydo") {
        Some("Wolfram SSH".to_string())
    } else {
        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        if parts.len() >= 3 {
            let product_part = parts[2..].join("-");
            product_part
                .split_whitespace()
                .next()
                .map(|w| w.to_string())
        } else {
            None
        }
    }
}
