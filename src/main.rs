use std::env;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use ipnetwork::IpNetwork;

use port_sniffer::{scan_ports, ScanConfig};

struct Arguments {
    ipaddr: IpAddr,
    threads: u16,
    enable_service_detection: bool,
    deep_inspection: bool,
    ports: Option<Vec<u16>>,
    output_json: bool,
}

fn parse_port_range(s: &str) -> Result<Vec<u16>, &'static str> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((start, end)) = part.split_once('-') {
            let lo = start.trim().parse::<u16>().map_err(|_| "Invalid port in range")?;
            let hi = end.trim().parse::<u16>().map_err(|_| "Invalid port in range")?;
            if lo > hi { return Err("Range start > end"); }
            for p in lo..=hi { ports.push(p); }
        } else {
            ports.push(part.parse::<u16>().map_err(|_| "Invalid port number")?);
        }
    }
    if ports.is_empty() { return Err("Empty port range"); }
    Ok(ports)
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("Not enough arguments");
        }

        let mut threads = 4;
        let mut enable_service_detection = true;
        let mut deep_inspection = false;
        let mut ipaddr_str = String::new();
        let mut ports: Option<Vec<u16>> = None;
        let mut output_json = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    println!(
                        "Usage: [-j <threads>] [--port-range <range>] [--no-service] [--deep] [--json] <ipaddr>\n\
                        -j <threads>        Number of threads to use (default: 4)\n\
                        --port-range <r>    Port range (e.g. 22,80,443 or 1-1000)\n\
                        --no-service        Disable service detection\n\
                        --deep              Enable deep inspection for services\n\
                        --json              Output results as JSON\n\
                        <ipaddr>            Target IP address"
                    );
                    return Err("help");
                }
                "-j" => {
                    if i + 1 >= args.len() {
                        return Err("-j requires <threads> argument");
                    }
                    threads = match args[i + 1].parse::<u16>() {
                        Ok(t) => t,
                        Err(_) => return Err("Failed to parse number of threads"),
                    };
                    i += 2;
                }
                "--port-range" => {
                    if i + 1 >= args.len() {
                        return Err("--port-range requires an argument");
                    }
                    ports = Some(parse_port_range(&args[i + 1])?);
                    i += 2;
                }
                "--no-service" => {
                    enable_service_detection = false;
                    i += 1;
                }
                "--deep" => {
                    deep_inspection = true;
                    i += 1;
                }
                "--json" => {
                    output_json = true;
                    i += 1;
                }
                arg => {
                    if !ipaddr_str.is_empty() {
                        return Err("Only one IP address allowed");
                    }
                    ipaddr_str = arg.to_string();
                    i += 1;
                }
            }
        }

        if ipaddr_str.is_empty() {
            return Err("No IP address specified");
        }

        let ipaddr = match IpAddr::from_str(&ipaddr_str) {
            Ok(ip) => ip,
            Err(_) => return Err("Invalid IP address, must be ipv4 or ipv6"),
        };

        Ok(Arguments {
            ipaddr,
            threads,
            enable_service_detection,
            deep_inspection,
            ports,
            output_json,
        })
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem parsing arguments: {}", program, err);
            process::exit(1);
        }
    });

    let config = ScanConfig {
        target: IpNetwork::from(arguments.ipaddr),
        threads: arguments.threads,
        timeout: 1000,
        delay: 0,
        randomize: false,
        enable_service_detection: arguments.enable_service_detection,
        syn_scan: false,
        deep_inspection: arguments.deep_inspection,
        ports: arguments.ports,
        log_sender: None,
        result_sender: None,
        cancel_signal: None,
        progress: None,
    };

    let results = scan_ports(config).await.unwrap_or_else(|err| {
        eprintln!("Engagement failed: {}", err);
        process::exit(1);
    });

    if arguments.output_json {
        let json = serde_json::to_string_pretty(&results).unwrap_or_else(|_| "[]".to_string());
        println!("{}", json);
    } else {
        for result in results {
            if let Some(service) = &result.service {
                let version_info = service.version.as_deref().unwrap_or("unknown version");
                let product_info = service.product.as_deref().unwrap_or("unknown product");
                println!("{} is open - {} {} ({})", result.port, service.name, version_info, product_info);
            } else {
                println!("{} is open", result.port);
            }
        }
    }
}
