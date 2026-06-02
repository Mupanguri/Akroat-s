use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

/// Grab a banner from a TCP service
pub async fn grab_banner(addr: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let socket_addr = format!("{}:{}", addr, port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buffer = [0; 1024];
            match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
                Ok(Ok(size)) if size > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..size]);
                    Some(banner.trim().to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Grab a banner with retries and exponential backoff
pub async fn grab_banner_with_retries(
    addr: &str,
    port: u16,
    timeout_ms: u64,
    retries: u8,
) -> Option<String> {
    let mut backoff = Duration::from_millis(100);
    for i in 0..retries {
        if let Some(banner) = grab_banner(addr, port, timeout_ms).await {
            if !banner.is_empty() {
                return Some(banner);
            }
        }
        if i < retries - 1 {
            sleep(backoff).await;
            backoff = backoff
                .saturating_mul(2)
                .min(Duration::from_millis(timeout_ms));
        }
    }
    None
}
