// Port sniffer library

use indicatif::ProgressBar;
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

/// Configuration for port scanning
#[derive(Clone)]
pub struct ScanConfig {
    pub ipaddr: IpAddr,
    pub threads: u16,
    pub timeout: u64,
    pub delay: u64,
    pub randomize: bool,
}

/// Result of scanning a single port
#[derive(Clone)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
}

impl PortResult {
    fn new(port: u16, is_open: bool) -> Self {
        Self {
            port,
            is_open,
            service: get_service_name(port),
        }
    }
}

/// Basic TCP connect port scanning
pub fn scan_ports(config: ScanConfig) -> Vec<PortResult> {
    let ports: Vec<u16> = (1..=1024).collect();
    let mut results = Vec::new();

    let pb = ProgressBar::new(ports.len() as u64);

    for port in ports {
        let result = scan_single_port(&config.ipaddr, port, config.timeout);
        results.push(result);
        pb.inc(1);

        if config.delay > 0 {
            std::thread::sleep(Duration::from_millis(config.delay));
        }
    }

    pb.finish_with_message("Scan complete");
    results.into_iter().filter(|r| r.is_open).collect()
}

fn scan_single_port(ip: &IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    let addr = (*ip, port).into();
    let timeout = Duration::from_millis(timeout_ms);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => PortResult::new(port, true),
        Err(_) => PortResult::new(port, false),
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
