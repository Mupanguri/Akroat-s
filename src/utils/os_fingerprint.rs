use std::net::TcpStream;
use std::time::Duration;

/// OS fingerprint result
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub guess: String,
    pub ttl: u32,
    pub window_size: u16,
    pub confidence: f32,
}

/// Guess the remote OS from TCP connection metrics.
/// Connects to the given port and reads the TTL.
pub fn fingerprint_os(ip: &str, port: u16, timeout_ms: u64) -> Option<OsFingerprint> {
    let addr = format!("{}:{}", ip, port);
    let timeout = Duration::from_millis(timeout_ms);

    if let Ok(stream) = TcpStream::connect_timeout(&addr.parse().ok()?, timeout) {
        let ttl = stream.ttl().ok()?;
        let window_size = 0;

        let guess = match ttl {
            0..=32 => "Some embedded / real-time OS".to_string(),
            33..=64 => "Linux / Unix".to_string(),
            65..=96 => "Windows 10 / 11 / Server 2022".to_string(),
            97..=128 => {
                "Windows 10 / 11 / Server 2019+".to_string()
            }
            129..=192 => {
                "Windows (older) / Cisco IOS".to_string()
            }
            193..=255 => {
                "Solaris / AIX / HP-UX".to_string()
            }
            _ => "Unknown".to_string(),
        };

        Some(OsFingerprint {
            guess,
            ttl,
            window_size,
            confidence: 0.5,
        })
    } else {
        None
    }
}
