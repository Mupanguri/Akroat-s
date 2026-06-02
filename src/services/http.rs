use crate::services::banner_grabber::grab_banner;
use crate::ServiceInfo;
use regex::Regex;
use reqwest::Client;
use reqwest::header::HeaderMap;
use std::sync::OnceLock;
use std::time::Duration;

/// Detected technology/app stack entry
#[derive(Debug, Clone)]
pub struct AppTech {
    pub name: String,
    pub version: Option<String>,
    pub certainty: f32,
}

static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

fn get_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(|| {
        Client::builder()
            .user_agent("Akroatis/1.0")
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default()
    })
}

/// Detect HTTP service and extract information
pub async fn detect_http(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    if let Some(banner) = grab_banner(ip, port, 5000).await {
        if banner.contains("HTTP/") || banner.contains("<html") || banner.contains("<!DOCTYPE") {
            let server = extract_server_header(&banner);
            if let Some(detailed_info) = probe_http_service(ip, port, deep).await {
                return Some(detailed_info);
            }
            return Some(ServiceInfo {
                name: "HTTP".to_string(),
                version: server,
                product: None,
                extrainfo: Some(format!(
                    "Banner: {}",
                    banner.chars().take(100).collect::<String>()
                )),
                cpe: None,
            });
        }
    }

    if let Some(info) = probe_http_service(ip, port, deep).await {
        return Some(info);
    }

    None
}

/// Probe HTTP service with a proper GET request
async fn probe_http_service(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    let client = get_client();

    let scheme = match port {
        443 | 8443 | 9443 => "https",
        _ => "http",
    };

    let url = format!("{}://{}:{}", scheme, ip, port);
    let response = client.get(&url).send().await.ok()?;

    let server = response
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let headers = response.headers().clone();
    let mut extrainfo_parts = Vec::new();

    let body = response.text().await.ok().unwrap_or_default();
    if let Some(title) = extract_html_title(&body) {
        extrainfo_parts.insert(0, format!("Title: {}", title));
    }

    if deep {
        let interesting_headers = [
            "X-Powered-By",
            "Content-Type",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ];
        for name in interesting_headers {
            if let Some(val) = headers.get(name).and_then(|h| h.to_str().ok()) {
                extrainfo_parts.push(format!("{}: {}", name, val));
            }
        }

        let cookie_str = headers
            .get(reqwest::header::SET_COOKIE)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        let apps = detect_app_stack(&headers, &body, cookie_str);
        for app in &apps {
            let ver = app
                .version
                .as_deref()
                .map(|v| format!(" {}", v))
                .unwrap_or_default();
            extrainfo_parts.push(format!("Tech: {}{}", app.name, ver));
        }

        let robots_url = format!("{}://{}:{}/robots.txt", scheme, ip, port);
        if let Ok(robots_res) = client.get(&robots_url).send().await {
            if robots_res.status().is_success() {
                if let Ok(text) = robots_res.text().await {
                    let preview: String = text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" | ");
                    if !preview.is_empty() {
                        extrainfo_parts.push(format!("Robots: {}", preview));
                    }
                }
            }
        }
    }

    Some(ServiceInfo {
        name: "HTTP".to_string(),
        version: server,
        product: None,
        extrainfo: if extrainfo_parts.is_empty() {
            None
        } else {
            Some(extrainfo_parts.join(" | "))
        },
        cpe: None,
    })
}

fn extract_server_header(response: &str) -> Option<String> {
    response
        .lines()
        .find(|line| line.to_lowercase().starts_with("server:"))
        .map(|server_line| server_line["Server:".len()..].trim().to_string())
}

fn extract_html_title(response: &str) -> Option<String> {
    static TITLE_RE: OnceLock<Regex> = OnceLock::new();
    let re = TITLE_RE.get_or_init(|| {
        Regex::new(r"(?i)<title[^>]*>(.*?)</title>").expect("Invalid title regex")
    });
    re.captures(response)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

pub fn detect_app_stack(headers: &HeaderMap, body: &str, _cookies: &str) -> Vec<AppTech> {
    let mut techs = Vec::new();

    if let Some(server) = headers
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
    {
        let server_lower = server.to_lowercase();
        if server_lower.contains("nginx") {
            let ver = extract_version(server, "nginx/");
            techs.push(AppTech {
                name: "Nginx".to_string(),
                version: ver,
                certainty: 1.0,
            });
        } else if server_lower.contains("apache") {
            let ver = extract_version(server, "apache/");
            techs.push(AppTech {
                name: "Apache HTTPD".to_string(),
                version: ver,
                certainty: 1.0,
            });
        } else if server_lower.contains("iis") {
            let ver = extract_version(server, "/");
            techs.push(AppTech {
                name: "IIS".to_string(),
                version: ver,
                certainty: 1.0,
            });
        } else if server_lower.contains("cloudflare") {
            techs.push(AppTech {
                name: "Cloudflare".to_string(),
                version: None,
                certainty: 1.0,
            });
        } else if server_lower.contains("caddy") {
            let ver = extract_version(server, "caddy/");
            techs.push(AppTech {
                name: "Caddy".to_string(),
                version: ver,
                certainty: 1.0,
            });
        } else if server_lower.contains("openresty") {
            techs.push(AppTech {
                name: "OpenResty".to_string(),
                version: None,
                certainty: 1.0,
            });
        }
    }

    if let Some(powered) = headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
    {
        let p = powered.to_lowercase();
        if p.contains("php") {
            let ver = extract_version(powered, "php/");
            techs.push(AppTech {
                name: "PHP".to_string(),
                version: ver,
                certainty: 0.9,
            });
        } else if p.contains("asp.net") {
            let ver = extract_version(powered, "asp.net");
            techs.push(AppTech {
                name: "ASP.NET".to_string(),
                version: ver,
                certainty: 0.9,
            });
        } else if p.contains("express") {
            techs.push(AppTech {
                name: "Express".to_string(),
                version: None,
                certainty: 0.8,
            });
        } else if p.contains("python") {
            techs.push(AppTech {
                name: "Python".to_string(),
                version: None,
                certainty: 0.7,
            });
        }
    }

    if let Some(gen) = headers
        .get("x-generator")
        .and_then(|v| v.to_str().ok())
    {
        let g = gen.to_lowercase();
        if g.contains("wordpress") || g.contains("wordpress") {
            let ver = extract_version(gen, "wordpress ");
            techs.push(AppTech {
                name: "WordPress".to_string(),
                version: ver,
                certainty: 0.9,
            });
        } else if g.contains("drupal") {
            techs.push(AppTech {
                name: "Drupal".to_string(),
                version: None,
                certainty: 0.9,
            });
        }
    }
    if headers.get("x-drupal-cache").is_some() {
        techs.push(AppTech {
            name: "Drupal".to_string(),
            version: None,
            certainty: 0.8,
        });
    }

    if let Some(cookie_str) = headers
        .get(reqwest::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        let c = cookie_str.to_lowercase();
        if c.contains("phpsessid") {
            techs.push(AppTech {
                name: "PHP".to_string(),
                version: None,
                certainty: 0.6,
            });
        }
        if c.contains("asp.net_sessionid") {
            techs.push(AppTech {
                name: "ASP.NET".to_string(),
                version: None,
                certainty: 0.6,
            });
        }
        if c.contains("jsessionid") {
            techs.push(AppTech {
                name: "Java".to_string(),
                version: None,
                certainty: 0.7,
            });
        }
        if c.contains("wp-") || c.contains("wordpress_logged") {
            techs.push(AppTech {
                name: "WordPress".to_string(),
                version: None,
                certainty: 0.7,
            });
        }
    }

    static META_GEN_RE: OnceLock<Regex> = OnceLock::new();
    let re = META_GEN_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)<meta[^>]+(?:name=["']generator["']|content=["']([^"']+)["'])[^>]*>"#,
        )
        .expect("Invalid meta regex")
    });
    if let Some(caps) = re.captures(body) {
        if let Some(content) = caps.get(1).or_else(|| {
            static ALT_GEN: OnceLock<Regex> = OnceLock::new();
            let r2 = ALT_GEN.get_or_init(|| {
                Regex::new(
                    r#"(?i)content=["']([^"']+)["'][^>]*name=["']generator["']"#,
                )
                .expect("Invalid meta regex")
            });
            r2.captures(body).and_then(|c| c.get(1))
        }) {
            let content = content.as_str().to_string();
            let lower = content.to_lowercase();
            if lower.contains("wordpress") {
                let ver = content.split_whitespace().find(|w| w.contains('.'));
                techs.push(AppTech {
                    name: "WordPress".to_string(),
                    version: ver.map(|v| v.to_string()),
                    certainty: 0.9,
                });
            } else if lower.contains("joomla") {
                let ver = content.split_whitespace().find(|w| w.contains('.'));
                techs.push(AppTech {
                    name: "Joomla".to_string(),
                    version: ver.map(|v| v.to_string()),
                    certainty: 0.9,
                });
            } else if lower.contains("drupal") {
                let ver = content.split_whitespace().find(|w| w.contains('.'));
                techs.push(AppTech {
                    name: "Drupal".to_string(),
                    version: ver.map(|v| v.to_string()),
                    certainty: 0.9,
                });
            } else if lower.contains("shopify") {
                techs.push(AppTech {
                    name: "Shopify".to_string(),
                    version: None,
                    certainty: 0.8,
                });
            } else if lower.contains("wix") {
                techs.push(AppTech {
                    name: "Wix".to_string(),
                    version: None,
                    certainty: 0.8,
                });
            } else if lower.contains("squarespace") {
                techs.push(AppTech {
                    name: "Squarespace".to_string(),
                    version: None,
                    certainty: 0.8,
                });
            } else {
                techs.push(AppTech {
                    name: content,
                    version: None,
                    certainty: 0.5,
                });
            }
        }
    }

    let body_lower = body.to_lowercase();
    if (body_lower.contains("wp-content") || body_lower.contains("wp-includes"))
        && !techs.iter().any(|t| t.name == "WordPress")
    {
        techs.push(AppTech {
            name: "WordPress".to_string(),
            version: None,
            certainty: 0.6,
        });
    }
    if body_lower.contains("joomla!") && !techs.iter().any(|t| t.name == "Joomla") {
        techs.push(AppTech {
            name: "Joomla".to_string(),
            version: None,
            certainty: 0.6,
        });
    }
    if body_lower.contains("laravel") {
        techs.push(AppTech {
            name: "Laravel".to_string(),
            version: None,
            certainty: 0.6,
        });
    }
    if body_lower.contains("symfony") {
        techs.push(AppTech {
            name: "Symfony".to_string(),
            version: None,
            certainty: 0.6,
        });
    }
    if body_lower.contains("django") {
        techs.push(AppTech {
            name: "Django".to_string(),
            version: None,
            certainty: 0.6,
        });
    }

    if headers.get("x-aspnet-version").is_some() {
        techs.push(AppTech {
            name: "ASP.NET".to_string(),
            version: None,
            certainty: 0.8,
        });
    }
    if headers.get("x-aspnetmvc-version").is_some() {
        techs.push(AppTech {
            name: "ASP.NET MVC".to_string(),
            version: None,
            certainty: 0.8,
        });
    }
    if (headers.get("x-drupal-cache").is_some()
        || headers.get("x-drupal-dynamic-cache").is_some())
        && !techs.iter().any(|t| t.name == "Drupal")
    {
        techs.push(AppTech {
            name: "Drupal".to_string(),
            version: None,
            certainty: 0.8,
        });
    }
    if headers.get("x-rack-cache").is_some() {
        techs.push(AppTech {
            name: "Ruby on Rails".to_string(),
            version: None,
            certainty: 0.6,
        });
    }

    techs
}

fn extract_version(text: &str, prefix: &str) -> Option<String> {
    text.find(prefix).and_then(|idx| {
        let rest = &text[idx + prefix.len()..];
        let ver: String = rest
            .chars()
            .take_while(|c| {
                c.is_ascii_digit() || *c == '.' || *c == '_' || *c == '-' || c.is_ascii_lowercase()
            })
            .collect();
        if ver.is_empty() {
            None
        } else {
            Some(ver)
        }
    })
}
