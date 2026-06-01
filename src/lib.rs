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
use serde::Serialize;

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
#[derive(Clone, Debug, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extrainfo: Option<String>,
    pub cpe: Option<String>,
}

/// Result of scanning a single port
#[derive(Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<ServiceInfo>,
    pub os_guess: Option<String>,
    pub tcp_window: Option<u16>,
    pub tcp_options: Vec<String>,
}

impl PortResult {
    fn new(port: u16, is_open: bool, service: Option<ServiceInfo>, os_guess: Option<String>, window: Option<u16>, options: Vec<String>) -> Self {
        Self {
            port,
            is_open,
            service,
            os_guess,
            tcp_window: window,
            tcp_options: options,
        }
    }
}

const UDP_PORTS: &[u16] = &[53, 67, 68, 161, 162, 137, 138, 500, 520, 1900, 5353];

/// Probe payload for DNS query (standard A-record query for "google.com")
fn dns_probe() -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(b"\x00\x01"); // TXID
    buf.extend_from_slice(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"); // flags + counts
    buf.extend_from_slice(b"\x06google\x03com\x00"); // QNAME
    buf.extend_from_slice(b"\x00\x01\x00\x01"); // QTYPE A + QCLASS IN
    buf
}

/// Probe payload for SNMP GET request (sysDescr.0 via community "public")
fn snmp_probe() -> Vec<u8> {
    vec![
        0x30, 0x26, // SEQUENCE
        0x02, 0x01, 0x01, // version 1
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community "public"
        0xa0, 0x19, // GetRequest PDU
        0x02, 0x02, 0x02, 0x37, // request-id 567
        0x02, 0x01, 0x00, // error-status 0
        0x02, 0x01, 0x00, // error-index 0
        0x30, 0x0f, // SEQUENCE of variable bindings
        0x30, 0x0d, // SEQUENCE
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID .1.3.6.1.2.1.1.1.0 (sysDescr)
        0x05, 0x00, // NULL value
    ]
}

fn get_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => dns_probe(),
        161 | 162 => snmp_probe(),
        _ => vec![0; 8], // generic probe
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

/// Pure TCP connect + UDP port scanning with optional service detection
pub async fn scan_ports(config: ScanConfig) -> Result<Vec<PortResult>, ScanError> {
    let is_cancelled = || config.cancel_signal.as_ref().is_some_and(|s| s.load(Ordering::SeqCst));

    let pps = if config.delay > 0 {
        (1000 / config.delay.max(1)).max(1)
    } else {
        2000
    };
    let pps_nonzero = NonZeroU32::new(pps as u32).expect("pps is clamped to >= 1");
    let lim = RateLimiter::direct(Quota::per_second(pps_nonzero));
    let lim = Arc::new(lim);

    let targets: Vec<IpAddr> = config.target.iter().collect();

    tracing::info!("Initializing engagement for {}", config.target);

    let mut ports: Vec<u16> = config.ports.clone().unwrap_or_else(|| (1..=65535).collect());

    if config.randomize {
        let mut rng = rand::rng();
        ports.shuffle(&mut rng);
    }

    let udp_ports: Vec<u16> = if config.udp_scan {
        let mut up = config.ports.clone().unwrap_or_else(|| UDP_PORTS.to_vec());
        if config.ports.is_none() {
            up = UDP_PORTS.to_vec();
        }
        if config.randomize {
            let mut rng = rand::rng();
            up.shuffle(&mut rng);
        }
        up
    } else {
        Vec::new()
    };

    let mut all_results = Vec::new();
    for ip in targets {
        if is_cancelled() { break; }

        // TCP scan
        let tcp_results: Vec<PortResult> = futures::stream::iter(ports.clone())
            .map(|port| {
                let config = config.clone();
                let lim = Arc::clone(&lim);
                let current_ip = ip;
                let cancel = config.cancel_signal.clone();

                async move {
                    if cancel.as_ref().is_some_and(|s| s.load(Ordering::SeqCst)) {
                        return PortResult::new(port, false, None, None, None, vec![]);
                    }

                    lim.until_ready().await;

                    if let Some(ref p) = config.progress {
                        p.fetch_add(1, Ordering::Relaxed);
                    }

                    if port % 1000 == 0 {
                        tracing::info!("TCP scanning {} (port {})", current_ip, port);
                    }
                    scan_single_port(&current_ip, port, config.timeout, config.enable_service_detection, config.deep_inspection).await
                }
            })
            .buffer_unordered(config.threads as usize)
            .filter(|r| futures::future::ready(r.is_open))
            .collect()
            .await;

        for res in &tcp_results {
            if let Some(ref sender) = config.result_sender {
                let _ = sender.send(res.clone());
            }
        }
        all_results.extend(tcp_results);

        if is_cancelled() {
            tracing::warn!("Scan cancelled by user");
            break;
        }

        // UDP scan
        if !udp_ports.is_empty() {
            tracing::info!("Starting UDP scan on {} ({} ports)", ip, udp_ports.len());
            let udp_results: Vec<PortResult> = futures::stream::iter(udp_ports.clone())
                .map(|port| {
                    let config = config.clone();
                    let current_ip = ip;
                    let cancel = config.cancel_signal.clone();

                    async move {
                        if cancel.as_ref().is_some_and(|s| s.load(Ordering::SeqCst)) {
                            return PortResult::new(port, false, None, None, None, vec![]);
                        }

                        if let Some(ref p) = config.progress {
                            p.fetch_add(1, Ordering::Relaxed);
                        }

                        scan_udp_port(&current_ip, port, config.timeout, config.enable_service_detection).await
                    }
                })
                .buffer_unordered(config.threads as usize)
                .filter(|r| futures::future::ready(r.is_open))
                .collect()
                .await;

            for res in &udp_results {
                if let Some(ref sender) = config.result_sender {
                    let _ = sender.send(res.clone());
                }
            }
            all_results.extend(udp_results);
        }

        if is_cancelled() {
            tracing::warn!("Scan cancelled by user");
            break;
        }
    }

    Ok(all_results)
}

/// Scan a single UDP port by sending a probe and waiting for a response
async fn scan_udp_port(ip: &IpAddr, port: u16, timeout_ms: u64, detect: bool) -> PortResult {
    let timeout = Duration::from_millis(timeout_ms);

    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            let addr = SocketAddr::new(*ip, port);
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

async fn scan_single_port(ip: &IpAddr, port: u16, timeout_ms: u64, detect: bool, deep: bool) -> PortResult {
    let addr = SocketAddr::new(*ip, port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let mut service = if detect {
                let ip_str = ip.to_string();
                services::detect_service(&ip_str, port, deep)
            } else {
                get_service_name(port).map(|name| ServiceInfo {
                    name,
                    version: None,
                    product: None,
                    extrainfo: None,
                    cpe: None,
                })
            };

            // TLS certificate analysis for TLS-enabled ports
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

            PortResult::new(port, true, service, None, None, vec![])
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
