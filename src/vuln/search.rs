use std::sync::Arc;
use crate::vuln::engine::{SearchFilters, SearchResult, Severity, Version, VulnEngine};

/// Query type for the search dispatcher
#[derive(Debug, Clone)]
pub enum SploitQuery {
    CveId(String),
    EdbId(u32),
    Keyword(String),
    ServiceVersion { product: String, version: String },
    Combined { text: String, platform: Option<String>, etype: Option<String> },
}

/// Search dispatcher — routes queries to the optimal path
pub fn search(engine: &VulnEngine, query: &SploitQuery) -> Vec<SearchResult> {
    match query {
        SploitQuery::CveId(cve_id) => {
            let cve_upper = cve_id.to_uppercase();
            if let Some(record) = engine.cve_map.get(&cve_upper) {
                let exploits = engine.exploits_by_cve(&cve_upper);
                vec![SearchResult {
                    score: 1000.0, // exact match gets max score
                    vuln: Some(Arc::clone(record)),
                    exploit: exploits.first().cloned(),
                }]
            } else {
                // Fallback to keyword search on the CVE ID
                let filters = SearchFilters {
                    limit: 10,
                    ..Default::default()
                };
                engine.search(cve_id, &filters)
            }
        }
        SploitQuery::EdbId(edb_id) => {
            if let Some(exploit) = engine.exploit_by_id(*edb_id) {
                vec![SearchResult {
                    score: 1000.0,
                    vuln: None,
                    exploit: Some(exploit),
                }]
            } else {
                Vec::new()
            }
        }
        SploitQuery::Keyword(keyword) => {
            let filters = SearchFilters {
                limit: 20,
                ..Default::default()
            };
            engine.search(keyword, &filters)
        }
        SploitQuery::ServiceVersion { product, version } => {
            let sev = Severity::None;
            let vulns = engine.match_service(product, version, &sev);
            vulns
                .into_iter()
                .map(|v| {
                    let exploits = engine.exploits_by_cve(&v.id);
                    SearchResult {
                        score: v.severity.score() as f64 * 10.0,
                        vuln: Some(v),
                        exploit: exploits.first().cloned(),
                    }
                })
                .collect()
        }
        SploitQuery::Combined { text, platform, etype } => {
            let filters = SearchFilters {
                limit: 20,
                platform: platform.clone(),
                exploit_type: etype.clone(),
                ..Default::default()
            };
            engine.search(text, &filters)
        }
    }
}

/// Tokenize and normalize a search query
pub fn tokenize_query(query: &str) -> Vec<String> {
    query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2 && !STOP_WORDS.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Parse a raw query string into a SploitQuery
pub fn parse_query(raw: &str) -> SploitQuery {
    let trimmed = raw.trim();

    // CVE ID pattern
    if trimmed.len() >= 10
        && trimmed[..3].to_uppercase() == "CVE"
        && trimmed.contains('-')
    {
        return SploitQuery::CveId(trimmed.to_string());
    }

    // EDB ID pattern
    if let Some(stripped) = trimmed
        .strip_prefix("EDB-")
        .or_else(|| trimmed.strip_prefix("edb-"))
    {
        if let Ok(id) = stripped.parse::<u32>() {
            return SploitQuery::EdbId(id);
        }
    }

    // Service:Version pattern (e.g. "apache:2.4.38")
    if let Some((product, version)) = trimmed.split_once(':') {
        let version_parsed = Version::parse(version);
        if !version_parsed.0.is_empty() && !product.is_empty() {
            return SploitQuery::ServiceVersion {
                product: product.trim().to_string(),
                version: version.trim().to_string(),
            };
        }
    }

    // Platform/type pattern: "windows rce" or "linux local"
    let lower = trimmed.to_lowercase();
    let platforms = ["windows", "linux", "macos", "android", "ios", "bsd", "solaris"];
    let types = ["remote", "local", "dos", "webapps", "shellcode", "payload"];

    let platform = platforms.iter().find(|p| lower.contains(*p)).map(|p| p.to_string());
    let etype = types.iter().find(|t| lower.contains(*t)).map(|t| t.to_string());

    if platform.is_some() || etype.is_some() {
        SploitQuery::Combined {
            text: trimmed.to_string(),
            platform,
            etype,
        }
    } else {
        SploitQuery::Keyword(trimmed.to_string())
    }
}

/// Stop words filtered from search queries
const STOP_WORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "by", "with", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can", "need", "dare",
    "this", "that", "these", "those", "it", "its", "they", "them", "he",
    "she", "we", "you", "all", "each", "every", "both", "few", "more",
    "most", "some", "any", "no", "not", "only", "own", "same", "so",
    "than", "too", "very", "just", "about", "above", "after", "again",
    "then", "there", "under", "up", "down", "out", "off", "over",
];

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cve_id() {
        let q = parse_query("CVE-2021-41773");
        assert!(matches!(q, SploitQuery::CveId(_)));
    }

    #[test]
    fn test_parse_edb_id() {
        let q = parse_query("EDB-51193");
        assert!(matches!(q, SploitQuery::EdbId(_)));
    }

    #[test]
    fn test_parse_service_version() {
        let q = parse_query("apache:2.4.38");
        assert!(matches!(q, SploitQuery::ServiceVersion { .. }));
    }

    #[test]
    fn test_parse_combined() {
        let q = parse_query("windows remote exploit");
        assert!(matches!(q, SploitQuery::Combined { .. }));
    }

    #[test]
    fn test_parse_keyword() {
        let q = parse_query("apache directory traversal");
        assert!(matches!(q, SploitQuery::Keyword(_)));
    }

    #[test]
    fn test_tokenize_removes_stop_words() {
        let tokens = tokenize_query("the apache remote exploit");
        assert!(!tokens.contains(&"the".to_string()));
        assert!(tokens.contains(&"apache".to_string()));
    }
}
