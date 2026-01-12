use std::env;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;

use port_sniffer::{scan_ports, ScanConfig};

struct Arguments {
    ipaddr: IpAddr,
    threads: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("Not enough arguments");
        } else if args.len() > 4 {
            return Err("Too many arguments");
        }

        let f = args[1].clone();
        if let Ok(ipaddr) = IpAddr::from_str(&f) {
            return Ok(Arguments { ipaddr, threads: 4 });
        } else {
            let flag = args[1].clone();
            if (flag.contains("-h") || flag.contains("--help")) && args.len() == 2 {
                println!(
                    "Usage: -j to select how many threads to use\r\n       -h or --help to show this message"
                );
                return Err("help");
            } else if flag.contains("-h") || flag.contains("--help") {
                return Err("Too many arguments");
            } else if flag.contains("-j") {
                if args.len() != 4 {
                    return Err("Invalid syntax: -j requires <threads> <ipaddr>");
                }
                let threads = match args[2].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => return Err("Failed to parse number of threads"),
                };
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    Ok(s) => s,
                    Err(_) => return Err("Invalid IP address, must be ipv4 or ipv6"),
                };
                return Ok(Arguments { ipaddr, threads });
            } else {
                return Err("Invalid syntax");
            }
        }
    }
}

fn main() {
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
        ipaddr: arguments.ipaddr,
        threads: arguments.threads,
        timeout: 1000,
        delay: 0,
        randomize: false,
    };

    let results = scan_ports(config);
    for result in results {
        if let Some(service) = &result.service {
            println!("{} is open - {}", result.port, service);
        } else {
            println!("{} is open", result.port);
        }
    }
}
