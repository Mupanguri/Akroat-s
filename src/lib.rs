pub mod config;
pub mod services;
pub mod vuln;
pub mod utils;

use futures::StreamExt;
use ipnetwork::IpNetwork;
use rand::prelude::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::sync::mpsc::Sender;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use serde::{Deserialize, Serialize};

/// Configuration for port scanning
#[derive(Clone)]
pub struct ScanConfig {
    pub target: IpNetwork,
    pub threads: u16,
    pub timeout: u64,
    pub delay: u64,
    pub randomize: bool,
    pub enable_service_detection: bool,
    pub syn_scan: bool,
    pub deep_inspection: bool,
    pub ports: Option<Vec<u16>>,
    pub udp_scan: bool,
    pub result_sender: Option<Sender<PortResult>>,
    pub cancel_signal: Option<Arc<AtomicBool>>,
    pub progress: Option<Arc<AtomicU16>>,
}

#[derive(Debug, Clone)]
pub enum ScanError {
    PermissionDenied(String),
    SocketError(String),
    InterfaceNotFound(String),
    InternalError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::PermissionDenied(msg) => write!(f, "Permission denied: {}. Root/Admin privileges required for SYN scan.", msg),
            ScanError::SocketError(msg) => write!(f, "Socket error: {}", msg),
            ScanError::InterfaceNotFound(msg) => write!(f, "Interface error: {}", msg),
            ScanError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {}

/// Detailed service information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extrainfo: Option<String>,
    pub cpe: Option<String>,
}

/// Vulnerability matched by the engine against a detected service
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub exploit_count: usize,
}

/// Result of scanning a single port
#[derive(Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<ServiceInfo>,
    pub os_guess: Option<String>,
    pub tcp_window: Option<u16>,
    pub tcp_options: Vec<String>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

impl PortResult {
    pub fn new(port: u16, is_open: bool, service: Option<ServiceInfo>, os_guess: Option<String>, window: Option<u16>, options: Vec<String>) -> Self {
        Self {
            port,
            is_open,
            service,
            os_guess,
            tcp_window: window,
            tcp_options: options,
            vulnerabilities: Vec::new(),
        }
    }
}

const UDP_PORTS: &[u16] = &[53, 67, 68, 161, 162, 137, 138, 500, 520, 1900, 5353];

fn dns_probe() -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(b"\x00\x01");
    buf.extend_from_slice(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    buf.extend_from_slice(b"\x06google\x03com\x00");
    buf.extend_from_slice(b"\x00\x01\x00\x01");
    buf
}

fn snmp_probe() -> Vec<u8> {
    vec![
        0x30, 0x26,
        0x02, 0x01, 0x01,
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19,
        0x02, 0x02, 0x02, 0x37,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x0f,
        0x30, 0x0d,
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        0x05, 0x00,
    ]
}

fn get_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => dns_probe(),
        161 | 162 => snmp_probe(),
        _ => vec![0; 8],
    }
}

fn get_udp_service_name(port: u16) -> Option<String> {
    match port {
        53 => Some("DNS".to_string()),
        67 | 68 => Some("DHCP".to_string()),
        137 | 138 => Some("NetBIOS".to_string()),
        161 | 162 => Some("SNMP".to_string()),
        500 => Some("IKE".to_string()),
        520 => Some("RIP".to_string()),
        1900 => Some("SSDP".to_string()),
        5353 => Some("mDNS".to_string()),
        _ => None,
    }
}

/// A port sequence that knows its length — avoids pre-allocating Vec for full-range scans.
pub struct PortSeq {
    count: usize,
    iter: Box<dyn Iterator<Item = u16> + Send>,
}

impl PortSeq {
    fn new(count: usize, iter: Box<dyn Iterator<Item = u16> + Send>) -> Self {
        Self { count, iter }
    }

    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }
}

impl IntoIterator for PortSeq {
    type Item = u16;
    type IntoIter = Box<dyn Iterator<Item = u16> + Send>;
    fn into_iter(self) -> Self::IntoIter { self.iter }
}

/// Lazy port iterator — avoids pre-allocating Vec for full-range scans.
/// Uses modular arithmetic for O(1)-memory random permutation.
fn port_list(config: &ScanConfig) -> PortSeq {
    if let Some(ref ports) = config.ports {
        let count = ports.len();
        if config.randomize {
            let mut p = ports.clone();
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            p.shuffle(&mut rng);
            PortSeq::new(count, Box::new(p.into_iter()))
        } else {
            PortSeq::new(count, Box::new(ports.clone().into_iter()))
        }
    } else if config.randomize {
        PortSeq::new(65535, Box::new(RandomPortIter::new(1, 65535)))
    } else {
        PortSeq::new(65535, Box::new(1..=65535))
    }
}

/// O(1)-memory random port iterator using modular arithmetic.
/// Generates a full-cycle permutation of [start, end] with no duplicates.
struct RandomPortIter {
    start: u16,
    count: u32,
    step: u32,
    current: u32,
    i: u32,
}

impl RandomPortIter {
    fn new(start: u16, end: u16) -> Self {
        let count = (end as u32) - (start as u32) + 1;
        // Pick a step coprime to count. For 65535 (3*5*17*257) we use a number
        // that is odd and not divisible by any of these factors.
        let mut rng = rand::rng();
        use rand::Rng;
        let step = loop {
            let s: u32 = rng.random_range(1..count);
            if gcd(s, count) == 1 {
                break s;
            }
        };
        let offset: u32 = rng.random_range(0..count);
        Self {
            start,
            count,
            step,
            current: offset,
            i: 0,
        }
    }
}

impl Iterator for RandomPortIter {
    type Item = u16;
    fn next(&mut self) -> Option<u16> {
        if self.i >= self.count {
            return None;
        }
        let port = self.start + ((self.current + self.i * self.step) % self.count) as u16;
        self.i += 1;
        Some(port)
    }
}

fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn send_results(results: &[PortResult], sender: &Option<Sender<PortResult>>) {
    for res in results {
        if let Some(ref sender) = sender {
            let _ = sender.send(res.clone());
        }
    }
}

/// Build a scan stream for a batch of ports with shared rate-limiting, progress, and cancellation.
macro_rules! scan_stream {
    ($ports:expr, $config:expr, $lim:expr, $ip:expr, $label:expr, $scan:expr) => {{
        let ports = $ports;
        if ports.is_empty() {
            Vec::new()
        } else {
            tracing::info!("Starting {} scan on {} ({} ports)", $label, $ip, ports.len());
            let results: Vec<PortResult> = futures::stream::iter(ports.into_iter())
                .map(|port| {
                    let config = $config.clone();
                    let lim = Arc::clone(&$lim);
                    let current_ip = $ip;
                    let cancel = config.cancel_signal.clone();

                    async move {
                        if cancel.as_ref().is_some_and(|s| s.load(Ordering::SeqCst)) {
                            return PortResult::new(port, false, None, None, None, vec![]);
                        }
                        lim.until_ready().await;
                        if let Some(ref p) = config.progress {
                            p.fetch_add(1, Ordering::Relaxed);
                        }
                        ($scan)(current_ip, port, &config).await
                    }
                })
                .buffer_unordered($config.threads as usize)
                .filter(|r| futures::future::ready(r.is_open))
                .collect()
                .await;
            send_results(&results, &$config.result_sender);
            results
        }
    }};
}

/// Pure TCP connect + UDP port scanning with optional service detection
pub async fn scan_ports(config: ScanConfig) -> Result<Vec<PortResult>, ScanError> {
    let is_cancelled = || config.cancel_signal.as_ref().is_some_and(|s| s.load(Ordering::SeqCst));

    let pps = if config.delay > 0 {
        (1000 / config.delay.max(1)).max(1)
    } else {
        2000
    };
    let pps_nonzero = NonZeroU32::new(pps as u32).expect("pps is clamped to >= 1");
    let lim = Arc::new(RateLimiter::direct(Quota::per_second(pps_nonzero)));

    let targets: Vec<IpAddr> = config.target.iter().collect();
    tracing::info!("Initializing engagement for {}", config.target);

    let udp_ports: Vec<u16> = if config.udp_scan {
        let base = config.ports.clone().unwrap_or_else(|| UDP_PORTS.to_vec());
        if config.ports.is_none() {
            let mut up = UDP_PORTS.to_vec();
            if config.randomize {
                let mut rng = rand::rng();
                up.shuffle(&mut rng);
            }
            up
        } else if config.randomize {
            let mut rng = rand::rng();
            let mut p = base;
            p.shuffle(&mut rng);
            p
        } else {
            base
        }
    } else {
        Vec::new()
    };

    let mut all_results = Vec::new();
    for ip in targets {
        if is_cancelled() { break; }

        all_results.extend(scan_stream!(
            port_list(&config),
            config,
            lim,
            ip,
            "TCP",
            |ip: IpAddr, port: u16, cfg: &ScanConfig| {
                Box::pin(scan_single_port(ip, port, cfg.timeout, cfg.enable_service_detection, cfg.deep_inspection))
            }
        ));

        if is_cancelled() {
            tracing::warn!("Scan cancelled by user");
            break;
        }

        all_results.extend(scan_stream!(
            udp_ports.clone(),
            config,
            lim,
            ip,
            "UDP",
            |ip: IpAddr, port: u16, cfg: &ScanConfig| {
                Box::pin(scan_udp_port(ip, port, cfg.timeout, cfg.enable_service_detection))
            }
        ));

        if is_cancelled() {
            tracing::warn!("Scan cancelled by user");
            break;
        }
    }

    Ok(all_results)
}

async fn scan_udp_port(ip: IpAddr, port: u16, timeout_ms: u64, detect: bool) -> PortResult {
    let timeout = Duration::from_millis(timeout_ms);

    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            let addr = SocketAddr::new(ip, port);
            let probe = get_udp_probe(port);

            if socket.send_to(&probe, addr).await.is_err() {
                return PortResult::new(port, false, None, None, None, vec![]);
            }

            let mut buf = [0; 1024];
            match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((size, _))) => {
                    let service = if detect {
                        let response = String::from_utf8_lossy(&buf[..size]);
                        Some(ServiceInfo {
                            name: get_udp_service_name(port).unwrap_or_else(|| "UDP".to_string()),
                            version: None,
                            product: None,
                            extrainfo: Some(response.trim().to_string()),
                            cpe: None,
                        })
                    } else {
                        get_udp_service_name(port).map(|name| ServiceInfo {
                            name,
                            version: None,
                            product: None,
                            extrainfo: None,
                            cpe: None,
                        })
                    };
                    PortResult::new(port, true, service, None, None, vec![])
                }
                _ => PortResult::new(port, false, None, None, None, vec![]),
            }
        }
        Err(_) => PortResult::new(port, false, None, None, None, vec![]),
    }
}

async fn scan_single_port(ip: IpAddr, port: u16, timeout_ms: u64, detect: bool, deep: bool) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let mut service = if detect {
                let ip_str = ip.to_string();
                services::detect_service(&ip_str, port, deep).await
            } else {
                get_service_name(port).map(|name| ServiceInfo {
                    name,
                    version: None,
                    product: None,
                    extrainfo: None,
                    cpe: None,
                })
            };

            let mut vulns = Vec::new();
            if let Some(ref si) = service {
                if let (Some(product), Some(version)) = (&si.product, &si.version) {
                    if let Some(engine) = crate::vuln::exploit::get_engine() {
                        for v in engine.match_service(product, version, &crate::vuln::engine::Severity::None) {
                            vulns.push(VulnerabilityInfo {
                                cve_id: v.id.clone(),
                                severity: format!("{:?}", v.severity),
                                cvss_score: v.cvss_score,
                                description: v.description.clone(),
                                exploit_count: v.exploits.len(),
                            });
                        }
                    }
                }
            }

            if deep && services::tls::is_tls_port(port) {
                let ip_str = ip.to_string();
                if let Some(tls_info) = services::tls::analyze_tls(&ip_str, port, timeout_ms).await {
                    let tls_str = services::tls::format_tls_info(&tls_info);
                    if let Some(ref mut si) = service {
                        let existing = si.extrainfo.take().unwrap_or_default();
                        si.extrainfo = if existing.is_empty() {
                            Some(tls_str)
                        } else {
                            Some(format!("{} | {}", existing, tls_str))
                        };
                    }
                }
            }

            let ip_str = ip.to_string();
            let os_fp = tokio::task::spawn_blocking(move || {
                utils::os_fingerprint::fingerprint_os(&ip_str, port, timeout_ms)
            }).await.ok().flatten();

            let (os_guess, tcp_window, tcp_options) = if let Some(fp) = os_fp {
                (Some(fp.guess), Some(fp.window_size), vec![format!("TTL={}", fp.ttl)])
            } else {
                let _ = stream.local_addr();
                (None, None, vec![])
            };

            let mut result = PortResult::new(port, true, service, os_guess, tcp_window, tcp_options);
            result.vulnerabilities = vulns;
            result
        }
        _ => PortResult::new(port, false, None, None, None, vec![]),
    }
}

fn get_service_name(port: u16) -> Option<String> {
    match port {
        20 => Some("FTP-DATA".to_string()),
        21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("TELNET".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        143 => Some("IMAP".to_string()),
        443 => Some("HTTPS".to_string()),
        993 => Some("IMAPS".to_string()),
        995 => Some("POP3S".to_string()),
        _ => None,
    }
}
