use crate::services::banner_grabber::grab_banner_with_retries;

/// Detect FTP service and extract version information
pub async fn detect_ftp(ip: &str, port: u16) -> Option<crate::ServiceInfo> {
    if let Some(banner) = grab_banner_with_retries(ip, port, 3000, 1).await {
        if banner.to_lowercase().contains("ftp") {
            let version = extract_ftp_version(&banner);
            let product = extract_ftp_product(&banner);
            return Some(crate::ServiceInfo {
                name: "FTP".to_string(),
                version,
                product,
                extrainfo: Some(banner),
                cpe: None,
            });
        }
    }
    None
}

pub(crate) fn extract_ftp_version(banner: &str) -> Option<String> {
    use regex::Regex;
    let patterns = [
        Regex::new(r"(\d+\.\d+\.\d+)").ok()?,
        Regex::new(r"(\d+\.\d+)").ok()?,
        regex::Regex::new(r"Version[:\s]+(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"version[:\s]+(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"\bv(\d+\.\d+\.\d+)\b").ok()?,
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

pub(crate) fn extract_ftp_product(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("microsoft") || banner_lower.contains("msftp") {
        Some("Microsoft FTP Service".to_string())
    } else if banner_lower.contains("vsftpd") {
        Some("vsftpd".to_string())
    } else if banner_lower.contains("proftpd") {
        Some("ProFTPD".to_string())
    } else if banner_lower.contains("pure-ftpd") {
        Some("Pure-FTPd".to_string())
    } else if banner_lower.contains("wu-ftpd") {
        Some("WU-FTPD".to_string())
    } else if banner_lower.contains("filezilla") {
        Some("FileZilla FTP Server".to_string())
    } else if banner_lower.contains("serv-u") {
        Some("Serv-U FTP Server".to_string())
    } else if banner_lower.contains("ftp") {
        let words: Vec<&str> = banner.split_whitespace().collect();
        words
            .first()
            .filter(|w| w.to_lowercase().contains("ftp") && w.len() > 3)
            .map(|w| w.to_string())
    } else {
        None
    }
}
