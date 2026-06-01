pub mod banner_grabber;
pub mod ftp;
pub mod http;
pub mod ssh;
pub mod smb;
pub mod generic;

#[cfg(test)]
mod tests;

use crate::ServiceInfo;
use crate::services::{
    banner_grabber::grab_banner, // Fix: grab_banner_with_retries is not used here
    ftp::detect_ftp,
    http::detect_http,
    ssh::detect_ssh,
    generic::detect_generic_service,
};

struct Probe {
    name: &'static str,
    pattern: &'static str,
}

const PROBES: &[Probe] = &[
    Probe { name: "HTTP", pattern: r"(?i)HTTP/1\.[01]" },
    Probe { name: "SSH", pattern: r"^SSH-\d\.\d" },
    Probe { name: "FTP", pattern: r"^220.*FTP" },
    Probe { name: "MySQL", pattern: r"(?i)mysql" },
];

/// Detect service running on a specific port
pub fn detect_service(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    // 1. Try Probe Engine (Regex-based)
    if let Some(banner) = grab_banner(ip, port, 2000) {
        for probe in PROBES {
            if let Ok(re) = regex::Regex::new(probe.pattern) {
                if re.is_match(&banner) {
                    return Some(ServiceInfo {
                        name: probe.name.to_string(),
                        version: None, // Logic for capture groups could go here
                        product: None,
                        extrainfo: Some(banner),
                        cpe: None,
                    });
                }
            }
        }
    }

    // 2. Fallback to specialized detection
    // Try service-specific detection first based on common ports
    match port {
        // FTP
        20 | 21 => {
            if let Some(info) = detect_ftp(ip, port) {
                return Some(info);
            }
        }
        // SSH
        22 => {
            if let Some(info) = detect_ssh(ip, port) {
                return Some(info);
            }
        }
        // Telnet
        23 => {
            // Try generic detection for telnet
            if let Some(info) = detect_generic_service(ip, port, "telnet", deep) {
                return Some(info);
            }
        }
        // SMTP
        25 => {
            if let Some(info) = detect_generic_service(ip, port, "smtp", deep) {
                return Some(info);
            }
        }
        // DNS
        53 => {
            // DNS detection would require UDP, skip for now
            if let Some(info) = detect_generic_service(ip, port, "dns", deep) {
                return Some(info);
            }
        }
        // HTTP
        80 => {
            if let Some(info) = detect_http(ip, port, deep) {
                return Some(info);
            }
        }
        // POP3
        110 => {
            if let Some(info) = detect_generic_service(ip, port, "pop3", deep) {
                return Some(info);
            }
        }
        // IMAP
        143 => {
            if let Some(info) = detect_generic_service(ip, port, "imap", deep) {
                return Some(info);
            }
        }
        // HTTPS
        443 => {
            // For now, treat HTTPS like HTTP for basic detection
            if let Some(info) = detect_http(ip, port, deep) {
                return Some(info);
            }
        }
        // IMAPS
        993 => {
            if let Some(info) = detect_generic_service(ip, port, "imaps", deep) {
                return Some(info);
            }
        }
        // POP3S
        995 => {
            if let Some(info) = detect_generic_service(ip, port, "pop3s", deep) {
                return Some(info);
            }
        }
        _ => {}
    }
    
    // Fallback to generic banner grabbing and service detection
    detect_generic_service(ip, port, "", deep)
}