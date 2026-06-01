use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use x509_parser::prelude::{parse_x509_certificate, GeneralName};

const TLS_PORTS: &[u16] = &[443, 993, 995, 8443, 9443];

/// Info extracted from a TLS certificate
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sans: Vec<String>,
    pub tls_version: String,
}

pub fn is_tls_port(port: u16) -> bool {
    TLS_PORTS.contains(&port)
}

/// Analyze TLS certificate on a given host:port
pub async fn analyze_tls(ip: &str, port: u16, timeout_ms: u64) -> Option<TlsInfo> {
    let addr = format!("{}:{}", ip, port);
    let timeout = Duration::from_millis(timeout_ms);

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await.ok()?;
    let ip_addr: std::net::IpAddr = ip.parse().ok()?;
    let dns_name = ServerName::IpAddress(ip_addr.into());

    let connection = tokio::time::timeout(timeout, connector.connect(dns_name, stream)).await.ok()?;
    let connection = connection.ok()?;

    let (_, session) = connection.get_ref();
    let pv: Option<rustls::ProtocolVersion> = session.protocol_version();
    let tls_version = format!("{:?}", pv.unwrap_or(rustls::ProtocolVersion::TLSv1_3));

    let certs = session.peer_certificates()?;
    let first_cert = certs.first()?;
    let der = first_cert.as_ref();

    match parse_x509_certificate(der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
            let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

            let mut sans = Vec::new();
            for ext in cert.extensions() {
                match ext.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                        for name in &san.general_names {
                            match name {
                                GeneralName::DNSName(d) => sans.push(d.to_string()),
                                GeneralName::IPAddress(ip) => {
                                    if ip.len() == 4 {
                                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                                    } else if ip.len() == 16 {
                                        sans.push(format!("{:02x}{:02x}:{:02x}{:02x}:...:{:02x}{:02x}:{:02x}{:02x}",
                                            ip[0], ip[1], ip[2], ip[3],
                                            ip[12], ip[13], ip[14], ip[15]));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            Some(TlsInfo { subject, issuer, not_before, not_after, sans, tls_version })
        }
        Err(_) => None,
    }
}

/// Format TLS info as a multi-line string for extrainfo
pub fn format_tls_info(info: &TlsInfo) -> String {
    let sans = if info.sans.is_empty() {
        "none".to_string()
    } else {
        info.sans.join(", ")
    };
    format!(
        "TLS {} | Subject: {} | Issuer: {} | Valid: {} - {} | SANs: {}",
        info.tls_version, info.subject, info.issuer, info.not_before, info.not_after, sans
    )
}
