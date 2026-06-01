pub mod banner_grabber;
pub mod ftp;
pub mod http;
pub mod ssh;
pub mod smb;
pub mod generic;
pub mod tls;

#[cfg(test)]
mod tests;

use std::sync::OnceLock;
use crate::ServiceInfo;
use crate::services::{
    banner_grabber::grab_banner,
    ftp::detect_ftp,
    http::detect_http,
    ssh::detect_ssh,
    smb::detect_smb,
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

trait ServiceDetector: Send + Sync {
    fn ports(&self) -> &[u16];
    fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo>;
}

struct FtpDetector;
impl ServiceDetector for FtpDetector {
    fn ports(&self) -> &[u16] { &[20, 21] }
    fn detect(&self, ip: &str, port: u16, _deep: bool) -> Option<ServiceInfo> {
        detect_ftp(ip, port)
    }
}

struct SshDetector;
impl ServiceDetector for SshDetector {
    fn ports(&self) -> &[u16] { &[22] }
    fn detect(&self, ip: &str, port: u16, _deep: bool) -> Option<ServiceInfo> {
        detect_ssh(ip, port)
    }
}

struct HttpDetector;
impl ServiceDetector for HttpDetector {
    fn ports(&self) -> &[u16] { &[80, 443, 8080, 8443] }
    fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        detect_http(ip, port, deep)
    }
}

struct SmbDetector;
impl ServiceDetector for SmbDetector {
    fn ports(&self) -> &[u16] { &[139, 445] }
    fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        let mut info = detect_smb(ip, port)?;
        if deep {
            if let Some(shares) = smb::enumerate_smb_shares(ip, port) {
                let share_str = shares.join(" | ");
                let existing = info.extrainfo.take().unwrap_or_default();
                info.extrainfo = if existing.is_empty() {
                    Some(share_str)
                } else {
                    Some(format!("{} | {}", existing, share_str))
                };
            }
        }
        Some(info)
    }
}

struct HintedDetector {
    ports: &'static [u16],
    hint: &'static str,
}
impl ServiceDetector for HintedDetector {
    fn ports(&self) -> &[u16] { self.ports }
    fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        detect_generic_service(ip, port, self.hint, deep)
    }
}

fn registry() -> &'static [Box<dyn ServiceDetector>] {
    static REGISTRY: OnceLock<Vec<Box<dyn ServiceDetector>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        vec![
            Box::new(FtpDetector) as Box<dyn ServiceDetector>,
            Box::new(SshDetector),
            Box::new(HttpDetector),
            Box::new(SmbDetector),
            Box::new(HintedDetector { ports: &[23], hint: "telnet" }),
            Box::new(HintedDetector { ports: &[25], hint: "smtp" }),
            Box::new(HintedDetector { ports: &[53], hint: "dns" }),
            Box::new(HintedDetector { ports: &[110], hint: "pop3" }),
            Box::new(HintedDetector { ports: &[143], hint: "imap" }),
            Box::new(HintedDetector { ports: &[993], hint: "imaps" }),
            Box::new(HintedDetector { ports: &[995], hint: "pop3s" }),
        ]
    })
}

fn get_detector(port: u16) -> Option<&'static dyn ServiceDetector> {
    for d in registry().iter() {
        if d.ports().contains(&port) {
            return Some(d.as_ref());
        }
    }
    None
}

/// Detect service running on a specific port
pub fn detect_service(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    // 1. Try Probe Engine (Regex-based)
    if let Some(banner) = grab_banner(ip, port, 2000) {
        for probe in PROBES {
            if let Ok(re) = regex::Regex::new(probe.pattern) {
                if re.is_match(&banner) {
                    return Some(ServiceInfo {
                        name: probe.name.to_string(),
                        version: None,
                        product: None,
                        extrainfo: Some(banner),
                        cpe: None,
                    });
                }
            }
        }
    }

    // 2. Try trait-based dispatch
    if let Some(detector) = get_detector(port) {
        if let Some(info) = detector.detect(ip, port, deep) {
            return Some(info);
        }
    }
    
    // 3. Fallback to generic banner grabbing and service detection
    detect_generic_service(ip, port, "", deep)
}