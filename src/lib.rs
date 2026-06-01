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
use tokio::net::TcpStream;
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
    pub log_sender: Option<Sender<String>>,
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

/// Pure TCP connect port scanning with optional service detection
pub async fn scan_ports(config: ScanConfig) -> Result<Vec<PortResult>, ScanError> {
    let is_cancelled = || config.cancel_signal.as_ref().map_or(false, |s| s.load(Ordering::SeqCst));

    let pps = if config.delay > 0 {
        1000 / config.delay.max(1)
    } else {
        2000
    };
    let pps = pps.max(1);
    let lim = RateLimiter::direct(Quota::per_second(NonZeroU32::new(pps as u32).unwrap()));
    let lim = Arc::new(lim);

    let targets: Vec<IpAddr> = config.target.iter().collect();

    if let Some(ref logger) = config.log_sender {
        let _ = logger.send(format!("[*] Initializing engagement for {}...", config.target));
    }

    let mut ports: Vec<u16> = config.ports.clone().unwrap_or_else(|| (1..=65535).collect());

    if config.randomize {
        let mut rng = rand::rng();
        ports.shuffle(&mut rng);
    }

    let mut all_results = Vec::new();
    for ip in targets {
        if is_cancelled() { break; }

        let results: Vec<PortResult> = futures::stream::iter(ports.clone())
            .map(|port| {
                let config = config.clone();
                let lim = Arc::clone(&lim);
                let current_ip = ip;
                let cancel = config.cancel_signal.clone();

                async move {
                    if cancel.as_ref().map_or(false, |s| s.load(Ordering::SeqCst)) {
                        return PortResult::new(port, false, None, None, None, vec![]);
                    }

                    lim.until_ready().await;

                    if let Some(ref p) = config.progress {
                        p.fetch_add(1, Ordering::Relaxed);
                    }

                    if port % 1000 == 0 {
                        if let Some(ref logger) = config.log_sender {
                            let _ = logger.send(format!("[+] Scanning {} (port {})...", current_ip, port));
                        }
                    }
                    scan_single_port(&current_ip, port, config.timeout, config.enable_service_detection, config.deep_inspection).await
                }
            })
            .buffer_unordered(config.threads as usize)
            .filter(|r| futures::future::ready(r.is_open))
            .collect()
            .await;

        for res in &results {
            if let Some(ref sender) = config.result_sender {
                let _ = sender.send(res.clone());
            }
        }
        all_results.extend(results);

        if is_cancelled() {
            if let Some(ref logger) = config.log_sender {
                let _ = logger.send("[!] Scan cancelled.".to_string());
            }
            break;
        }
    }

    Ok(all_results)
}

async fn scan_single_port(ip: &IpAddr, port: u16, timeout_ms: u64, detect: bool, deep: bool) -> PortResult {
    let addr = SocketAddr::new(*ip, port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let service = if detect {
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
