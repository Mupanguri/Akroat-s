pub mod banner_grabber;
pub mod ftp;
pub mod http;
pub mod ssh;
pub mod smb;
pub mod generic;
pub mod tls;

#[cfg(test)]
mod tests;

use crate::ServiceInfo;
use crate::services::{
    banner_grabber::grab_banner,
    ftp::detect_ftp,
    http::detect_http,
    ssh::detect_ssh,
    smb::detect_smb,
    generic::detect_generic_service,
};
use async_trait::async_trait;

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

#[async_trait]
trait ServiceDetector: Send + Sync {
    fn ports(&self) -> &[u16];
    async fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo>;
}

struct FtpDetector;
#[async_trait]
impl ServiceDetector for FtpDetector {
    fn ports(&self) -> &[u16] { &[20, 21] }
    async fn detect(&self, ip: &str, port: u16, _deep: bool) -> Option<ServiceInfo> {
        detect_ftp(ip, port).await
    }
}

struct SshDetector;
#[async_trait]
impl ServiceDetector for SshDetector {
    fn ports(&self) -> &[u16] { &[22] }
    async fn detect(&self, ip: &str, port: u16, _deep: bool) -> Option<ServiceInfo> {
        detect_ssh(ip, port).await
    }
}

struct HttpDetector;
#[async_trait]
impl ServiceDetector for HttpDetector {
    fn ports(&self) -> &[u16] { &[80, 443, 8080, 8443] }
    async fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        detect_http(ip, port, deep).await
    }
}

struct SmbDetector;
#[async_trait]
impl ServiceDetector for SmbDetector {
    fn ports(&self) -> &[u16] { &[139, 445] }
    async fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        let mut info = detect_smb(ip, port).await?;
        if deep {
            if let Some(shares) = smb::enumerate_smb_shares(ip, port).await {
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
#[async_trait]
impl ServiceDetector for HintedDetector {
    fn ports(&self) -> &[u16] { self.ports }
    async fn detect(&self, ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
        detect_generic_service(ip, port, self.hint, deep).await
    }
}

fn registry() -> &'static [Box<dyn ServiceDetector>] {
    static REGISTRY: std::sync::OnceLock<Vec<Box<dyn ServiceDetector>>> =
        std::sync::OnceLock::new();
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
pub async fn detect_service(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    // 1. Try Probe Engine (Regex-based)
    if let Some(banner) = grab_banner(ip, port, 2000).await {
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
        if let Some(info) = detector.detect(ip, port, deep).await {
            return Some(info);
        }
    }

    // 3. Fallback to generic banner grabbing
    detect_generic_service(ip, port, "", deep).await
}
