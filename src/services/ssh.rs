use crate::services::banner_grabber::grab_banner_with_retries;
use regex::Regex;

use crate::ServiceInfo;
/// Detect SSH service and extract version information
pub fn detect_ssh(ip: &str, port: u16) -> Option<ServiceInfo> {
    // SSH typically sends a banner immediately upon connection
    if let Some(banner) = grab_banner_with_retries(ip, port, 3000, 1) {
        // SSH banner usually starts with "SSH-" followed by protocol version
        if banner.starts_with("SSH-") {
            // Extract version from SSH banner (e.g., "SSH-2.0-OpenSSH_7.9")
            let version = extract_ssh_version(&banner);
            
            // Determine product from banner
            let product = extract_ssh_product(&banner);
            
            return Some(ServiceInfo {
                name: "SSH".to_string(),
                version,
                product,
                extrainfo: Some(banner),
                cpe: None, // Could be enhanced with CPE mapping
            });
        }
    }
    
    None
}

/// Extract version from SSH banner
pub(crate) fn extract_ssh_version(banner: &str) -> Option<String> {
    // SSH banner format: SSH-<protocol>-<comments>
    // Example: SSH-2.0-OpenSSH_7.9p1 Ubuntu-10
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() >= 3 {
        // The version info is in the third part and beyond
        let version_part = parts[2..].join("-");
        // Extract just the version numbers
        let re = Regex::new(r"[\d\.]+(?:p\d+)?").ok()?;
        re.find(&version_part).map(|m| m.as_str().to_string())
    } else {
        None
    }
}

/// Extract product from SSH banner
pub(crate) fn extract_ssh_product(banner: &str) -> Option<String> {
    // Common SSH implementations
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
        // Try to extract product name from banner
        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        if parts.len() >= 3 {
            let product_part = parts[2..].join("-");
            // Take first word as product
            product_part.split_whitespace().next().map(|first_word| first_word.to_string())
        } else {
            None
        }
    }
}