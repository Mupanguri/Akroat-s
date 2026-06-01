use std::io::Read; // Fix: Remove unused Write import
use std::net::TcpStream;
use std::time::Duration;

/// Grab a banner from a TCP service
///
/// # Arguments
/// * `addr` - The IP address to connect to
/// * `port` - The port to connect to
/// * `timeout` - Timeout in milliseconds
///
/// # Returns
/// * `Option<String>` - The banner if successful, None otherwise
pub fn grab_banner(addr: &str, port: u16, timeout: u64) -> Option<String> {
    let socket_addr = format!("{}:{}", addr, port);
    match TcpStream::connect_timeout(&socket_addr.parse().ok()?, Duration::from_millis(timeout)) {
        Ok(mut stream) => {
            // Set read timeout
            stream.set_read_timeout(Some(Duration::from_millis(timeout))).ok()?;
            
            // Try to read up to 1024 bytes
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer) {
                Ok(size) if size > 0 => {
                    // Convert to string, replacing invalid UTF-8
                    let banner = String::from_utf8_lossy(&buffer[..size]);
                    Some(banner.trim().to_string())
                }
                _ => None,
            }
        }
        Err(_) => None,
    }
}

/// Try to grab a banner with multiple attempts
/// Uses an exponential backoff strategy to handle jittery network environments.
pub fn grab_banner_with_retries(addr: &str, port: u16, timeout: u64, retries: u8) -> Option<String> {
    let mut backoff = Duration::from_millis(100);
    for i in 0..retries {
        if let Some(banner) = grab_banner(addr, port, timeout) {
            if !banner.is_empty() {
                return Some(banner);
            }
        }
        if i < retries - 1 {
            std::thread::sleep(backoff);
            // Exponentially increase the backoff, capped at the connection timeout
            backoff = backoff.saturating_mul(2).min(Duration::from_millis(timeout));
        }
    }
    None
}