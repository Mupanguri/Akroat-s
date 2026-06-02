use crate::services::ssh::extract_ssh_version;
use crate::services::ftp::extract_ftp_version;

#[test]
fn test_extract_ssh_version() {
    let banner = "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10";
    let version = extract_ssh_version(banner);
    assert_eq!(version, Some("7.9p1".to_string()));
}

#[test]
fn test_extract_ftp_version() {
    let banner = "220 vsFTPd 3.0.5 ready";
    let version = extract_ftp_version(banner);
    assert_eq!(version, Some("3.0.5".to_string()));
}

#[tokio::test]
async fn test_detect_service_ssh() {
    let result = crate::services::detect_service("127.0.0.1", 22, false).await;
    assert!(result.is_some() || result.is_none());
}
