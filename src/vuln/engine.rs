use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use lasso::{Rodeo, Spur};

// ─── Version ───────────────────────────────────────────────────────────────

/// Encoded version for fast comparison: "2.4.38" → [2, 4, 38]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version(pub Vec<u32>);

impl Version {
    pub fn parse(s: &str) -> Self {
        let segs: Vec<u32> = s
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|p| p.parse::<u32>().ok())
            .collect();
        Version(if segs.is_empty() { vec![0] } else { segs })
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let max_len = self.0.len().max(other.0.len());
        for i in 0..max_len {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

// ─── Version Bound ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Bound {
    Inclusive(Version),
    Exclusive(Version),
    Unbounded,
}

impl Bound {
    pub fn version(&self) -> Option<&Version> {
        match self {
            Bound::Inclusive(v) | Bound::Exclusive(v) => Some(v),
            Bound::Unbounded => None,
        }
    }
}

// ─── Version Interval ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VersionInterval {
    pub start: Bound,
    pub end: Bound,
    pub cve_id: String,
}

// ─── Severity ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::None,
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::None => 1,
        }
    }
}

// ─── Vulnerability Record ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnRecord {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub affected_cpe: Vec<String>,
    pub fixed_cpe: Vec<String>,
    pub references: Vec<String>,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub exploits: Vec<ExploitRecord>,
}

// ─── Exploit Record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitRecord {
    pub edb_id: u32,
    pub title: String,
    pub platform: String,
    pub exploit_type: String,
    pub verified: bool,
    pub url: String,
    pub author: Option<String>,
    pub date: Option<String>,
    pub cve_ids: Vec<String>,
}

// ─── Search Result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub score: f64,
    pub vuln: Option<Arc<VulnRecord>>,
    pub exploit: Option<Arc<ExploitRecord>>,
}

// ─── Search Filters ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SearchFilters {
    pub min_severity: Severity,
    pub platform: Option<String>,
    pub exploit_type: Option<String>,
    pub limit: usize,
}

impl Default for VulnEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Inverted Index ─────────────────────────────────────────────────────────

type PostingList = Vec<(u32, u32)>;

// ─── CPE Index ──────────────────────────────────────────────────────────────

pub struct CpeIndex {
    map: HashMap<Spur, Vec<String>>,
    interner: Rodeo,
}

impl Default for CpeIndex {
    fn default() -> Self { Self::new() }
}

impl CpeIndex {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            interner: Rodeo::new(),
        }
    }

    pub fn insert(&mut self, vendor: &str, product: &str, cve_id: &str) {
        let key = format!("{}:{}", vendor, product);
        let interned = self.interner.get_or_intern(&key);
        self.map.entry(interned).or_default().push(cve_id.to_string());
    }

    pub fn lookup(&self, vendor: &str, product: &str) -> Option<&[String]> {
        let key = format!("{}:{}", vendor, product);
        let interned = self.interner.get(&key)?;
        self.map.get(&interned).map(|v| v.as_slice())
    }
}

// ─── CVE → Exploit Reverse Index ───────────────────────────────────────────

/// Maps CVE ID → EDB IDs for fast exploit lookup by CVE
pub struct CveExploitIndex {
    map: HashMap<String, Vec<u32>>,
}

impl Default for CveExploitIndex {
    fn default() -> Self { Self::new() }
}

impl CveExploitIndex {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn insert(&mut self, cve_id: &str, edb_id: u32) {
        self.map
            .entry(cve_id.to_string())
            .or_default()
            .push(edb_id);
    }

    pub fn lookup(&self, cve_id: &str) -> Option<&[u32]> {
        self.map.get(cve_id).map(|v| v.as_slice())
    }
}

// ─── Vulnerability Engine ───────────────────────────────────────────────────

pub struct VulnEngine {
    pub cve_map: HashMap<String, Arc<VulnRecord>>,
    pub edb_map: HashMap<u32, Arc<ExploitRecord>>,
    pub cpe_index: CpeIndex,
    pub cve_exploit_index: CveExploitIndex,
    pub version_intervals: Vec<VersionInterval>,
    inverted_index: HashMap<String, PostingList>,
    doc_lengths: Vec<u32>,
    /// doc_id → CVE ID for O(1) reverse lookup
    doc_id_to_cve: Vec<String>,
    avgdl: f64,
    num_docs: u32,
}

impl VulnEngine {
    pub fn new() -> Self {
        Self {
            cve_map: HashMap::new(),
            edb_map: HashMap::new(),
            cpe_index: CpeIndex::new(),
            cve_exploit_index: CveExploitIndex::new(),
            version_intervals: Vec::new(),
            inverted_index: HashMap::new(),
            doc_lengths: Vec::new(),
            doc_id_to_cve: Vec::new(),
            avgdl: 0.0,
            num_docs: 0,
        }
    }

    /// Insert a vulnerability record and index it
    pub fn insert_vuln(&mut self, record: VulnRecord) {
        let cve_id = record.id.clone();
        let record = Arc::new(record);

        // Index CPEs for product-based matching
        for cpe in &record.affected_cpe {
            if let Some((vendor, product)) = Self::parse_cpe_uri(cpe) {
                self.cpe_index.insert(&vendor, &product, &cve_id);
            }
        }

        // Build a single combined version interval per CVE:
        //   start = min version from affected_cpe (Inclusive) or Unbounded
        //   end   = min version from fixed_cpe   (Exclusive) or Unbounded
        let mut start_ver: Option<Version> = None;
        let mut end_ver: Option<Version> = None;

        for cpe in &record.affected_cpe {
            if let Some((_, _, ver_str, _)) = Self::parse_cpe_with_version(cpe) {
                let ver = Version::parse(&ver_str);
                if start_ver.as_ref().is_none_or(|s| ver < *s) {
                    start_ver = Some(ver);
                }
            }
        }

        for cpe in &record.fixed_cpe {
            if let Some((_, _, ver_str, _)) = Self::parse_cpe_with_version(cpe) {
                let ver = Version::parse(&ver_str);
                if end_ver.as_ref().is_none_or(|e| ver < *e) {
                    end_ver = Some(ver);
                }
            }
        }

        self.version_intervals.push(VersionInterval {
            start: start_ver.map_or(Bound::Unbounded, Bound::Inclusive),
            end: end_ver.map_or(Bound::Unbounded, Bound::Exclusive),
            cve_id: cve_id.clone(),
        });

        // Index exploits for reverse lookup
        for exploit in &record.exploits {
            self.cve_exploit_index.insert(&cve_id, exploit.edb_id);
        }

        // Build inverted index
        let doc_id = self.num_docs;
        self.num_docs += 1;
        self.doc_id_to_cve.push(cve_id.clone());
        let tokens = Self::tokenize(&format!("{} {}", record.id, record.description));
        let mut term_freqs: HashMap<String, u32> = HashMap::new();
        for t in &tokens {
            *term_freqs.entry(t.clone()).or_default() += 1;
        }
        self.doc_lengths.push(tokens.len() as u32);
        for (term, freq) in term_freqs {
            self.inverted_index
                .entry(term)
                .or_default()
                .push((doc_id, freq));
        }

        self.cve_map.insert(cve_id, record);
    }

    /// Insert an exploit record
    pub fn insert_exploit(&mut self, record: ExploitRecord) {
        let edb_id = record.edb_id;
        for cve in &record.cve_ids {
            self.cve_exploit_index.insert(cve, edb_id);
        }
        self.edb_map.insert(edb_id, Arc::new(record));
    }

    /// Finalize: sort intervals, compute avgdl
    pub fn finalize(&mut self) {
        self.version_intervals.sort_by(|a, b| {
            let a_start = a.start.version().map(|v| v.as_slice()).unwrap_or(&[]);
            let b_start = b.start.version().map(|v| v.as_slice()).unwrap_or(&[]);
            a_start.cmp(b_start)
        });

        let total: u64 = self.doc_lengths.iter().map(|&l| l as u64).sum();
        let count = self.doc_lengths.len().max(1);
        self.avgdl = total as f64 / count as f64;
    }

    /// Match a service (product + version) to known vulnerabilities
    pub fn match_service(&self, product: &str, version: &str, min_severity: &Severity) -> Vec<Arc<VulnRecord>> {
        let ver = Version::parse(version);
        let mut matched = Vec::new();

        let pos = self.version_intervals.partition_point(|iv| {
            iv.start.version().map(|v| v.as_slice()).unwrap_or(&[]) <= ver.as_slice()
        });

        let mut seen = std::collections::HashSet::new();
        for iv in &self.version_intervals[..pos] {
            match &iv.end {
                Bound::Exclusive(end) if ver >= *end => continue,
                Bound::Inclusive(end) if ver > *end => continue,
                _ => {}
            }
            match &iv.start {
                Bound::Exclusive(start) if ver <= *start => continue,
                Bound::Inclusive(start) if ver < *start => continue,
                _ => {}
            }

            if !seen.insert(&iv.cve_id) {
                continue;
            }

            if let Some(record) = self.cve_map.get(&iv.cve_id) {
                if record.severity >= *min_severity {
                    let p_lower = product.to_lowercase();
                    let cpe_match = record.affected_cpe.iter().any(|cpe| {
                        let cpe_lower = cpe.to_lowercase();
                        cpe_lower.contains(&p_lower)
                            || Self::parse_cpe_uri(cpe).is_some_and(|(vendor, _)| {
                                p_lower.contains(&vendor)
                            })
                    });
                    if cpe_match || record.affected_cpe.is_empty() {
                        matched.push(Arc::clone(record));
                    }
                }
            }
        }

        matched.sort_by(|a, b| b.severity.cmp(&a.severity));
        matched
    }

    /// Full-text search using BM25 with custom boosts
    pub fn search(&self, query: &str, filters: &SearchFilters) -> Vec<SearchResult> {
        let tokens = Self::tokenize(query);
        if tokens.is_empty() {
            return Vec::new();
        }

        let k1 = 1.2f64;
        let b = 0.75f64;
        let n = self.num_docs.max(1) as f64;

        let mut scores: HashMap<u32, f64> = HashMap::new();

        for term in &tokens {
            let df = self.inverted_index.get(term).map(|p| p.len()).unwrap_or(0) as f64;
            if df == 0.0 {
                continue;
            }
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

            if let Some(postings) = self.inverted_index.get(term) {
                for &(doc_id, tf) in postings {
                    let doc_len = self.doc_lengths.get(doc_id as usize).copied().unwrap_or(1) as f64;
                    let tf_component = (tf as f64 * (k1 + 1.0))
                        / (tf as f64 + k1 * (1.0 - b + b * doc_len / self.avgdl));
                    *scores.entry(doc_id).or_default() += idf * tf_component;
                }
            }
        }

        let mut results: Vec<SearchResult> = Vec::new();
        for (doc_id, score) in scores {
            let cve_id = match self.doc_id_to_cve.get(doc_id as usize) {
                Some(k) => k.clone(),
                None => continue,
            };
            let vuln = match self.cve_map.get(&cve_id) {
                Some(v) => v,
                None => continue,
            };

            if vuln.severity < filters.min_severity {
                continue;
            }

            if let Some(ref platform) = filters.platform {
                let has_p = vuln.exploits.iter().any(|e| {
                    e.platform.to_lowercase().contains(&platform.to_lowercase())
                });
                if !has_p {
                    continue;
                }
            }

            if let Some(ref etype) = filters.exploit_type {
                let has_t = vuln.exploits.iter().any(|e| {
                    e.exploit_type.to_lowercase().contains(&etype.to_lowercase())
                });
                if !has_t {
                    continue;
                }
            }

            let exploit_boost = if vuln.exploits.iter().any(|e| e.verified) {
                2.0
            } else if !vuln.exploits.is_empty() {
                1.0
            } else {
                0.0
            };

            let sev_boost = vuln.severity.score() as f64 * 0.5;

            results.push(SearchResult {
                score: score + exploit_boost + sev_boost,
                vuln: Some(Arc::clone(vuln)),
                exploit: None,
            });
        }

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
        let limit = filters.limit.max(1);
        results.truncate(limit);

        results
    }

    /// Look up an exploit by EDB ID
    pub fn exploit_by_id(&self, edb_id: u32) -> Option<Arc<ExploitRecord>> {
        self.edb_map.get(&edb_id).map(Arc::clone)
    }

    /// Get all exploits for a CVE ID
    pub fn exploits_by_cve(&self, cve_id: &str) -> Vec<Arc<ExploitRecord>> {
        self.cve_exploit_index
            .lookup(cve_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|edb_id| self.edb_map.get(edb_id))
                    .map(Arc::clone)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_cpe_uri(cpe: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() >= 5 {
            Some((parts[3].to_string(), parts[4].to_string()))
        } else {
            None
        }
    }

    fn parse_cpe_with_version(cpe: &str) -> Option<(String, String, String, bool)> {
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() < 6 {
            return None;
        }
        let vendor = parts[3].to_string();
        let product = parts[4].to_string();
        let version = parts[5].to_string();
        if version == "*" {
            return None;
        }
        Some((vendor, product, version, false))
    }

    fn tokenize(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .map(|t| t.to_lowercase())
            .collect()
    }
}
