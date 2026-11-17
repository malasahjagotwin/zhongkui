//! Perintah `keris deps`: cek lockfile ke database kerentanan OSV.
//!
//! OSV dipilih karena API-nya publik, gratis, dan tidak butuh kredensial —
//! jadi fitur ini tetap bisa dipakai tanpa memberi tahu siapa pun paket apa
//! yang kita pakai... kecuali ke OSV sendiri. Pakai `--offline` kalau itu pun
//! tidak diinginkan.

use crate::cli::DepsArgs;
use crate::finding::{Finding, Severity, Source};
use crate::report;
use crate::rules;
use anyhow::{Context, Result, bail};
use serde::Deserialize;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_ECOSYSTEM: &str = "crates.io";
/// OSV membatasi jumlah query per permintaan.
const CHUNK_SIZE: usize = 500;

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    /// Paket tanpa `source` adalah crate lokal (workspace), bukan dari registry.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvResult>,
}

#[derive(Deserialize, Default)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

impl OsvVuln {
    /// OSV menyimpan tingkat keparahan di `database_specific.severity` untuk
    /// sumber GHSA. Kalau tidak ada, kita tidak menebak-nebak dan pakai
    /// Medium sebagai default yang jelas-jelas konservatif.
    fn severity(&self) -> Severity {
        self.database_specific
            .as_ref()
            .and_then(|d| d.get("severity"))
            .and_then(|s| s.as_str())
            .and_then(Severity::parse_loose)
            .unwrap_or(Severity::Medium)
    }

    fn cve(&self) -> Option<&str> {
        self.aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(String::as_str)
    }
}

pub async fn run(args: DepsArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.lockfile)
        .with_context(|| format!("gagal membaca {}", args.lockfile.display()))?;

    let lockfile: Lockfile = toml::from_str(&content)
        .with_context(|| format!("{} bukan Cargo.lock yang valid", args.lockfile.display()))?;

    let packages: Vec<&LockPackage> = lockfile
        .package
        .iter()
        .filter(|p| p.source.as_deref().is_some_and(|s| s.contains("crates.io")))
        .collect();

    if packages.is_empty() {
        bail!(
            "tidak ada paket dari crates.io di {} — hanya Cargo.lock yang didukung saat ini",
            args.lockfile.display()
        );
    }

    eprintln!("→ {} paket dari crates.io", packages.len());

    let lock_display = args
        .lockfile
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| args.lockfile.display().to_string());

    if args.offline {
        for p in &packages {
            println!("  {} {}", p.name, p.version);
        }
        eprintln!("→ mode offline: API OSV tidak dipanggil");
        return Ok(());
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("gagal membangun HTTP client")?;

    let mut findings = Vec::new();

    for (chunk_idx, chunk) in packages.chunks(CHUNK_SIZE).enumerate() {
        eprintln!(
            "→ query OSV batch {}/{} ({} paket)",
            chunk_idx + 1,
            packages.len().div_ceil(CHUNK_SIZE),
            chunk.len()
        );

        let queries: Vec<serde_json::Value> = chunk
            .iter()
            .map(|p| {
                serde_json::json!({
                    "package": { "name": p.name, "ecosystem": OSV_ECOSYSTEM },
                    "version": p.version,
                })
            })
            .collect();

        let response = http
            .post(OSV_BATCH_URL)
            .json(&serde_json::json!({ "queries": queries }))
            .send()
            .await
            .context("permintaan ke OSV gagal")?;

        let status = response.status();
        let body = response.text().await.context("gagal membaca respons OSV")?;

        if !status.is_success() {
            bail!("OSV mengembalikan HTTP {status}: {}", body.chars().take(300).collect::<String>());
        }

        let parsed: OsvBatchResponse =
            serde_json::from_str(&body).context("respons OSV tidak bisa diparse")?;

        // `results` sejajar indeksnya dengan `queries`, jadi kalau jumlahnya
        // beda ada yang tidak beres dan kita berhenti daripada salah pasang.
        if parsed.results.len() != chunk.len() {
            bail!(
                "jumlah hasil OSV ({}) tidak cocok dengan jumlah query ({})",
                parsed.results.len(),
                chunk.len()
            );
        }

        for (package, result) in chunk.iter().zip(parsed.results) {
            for vuln in result.vulns {
                let cve = vuln.cve().map(|c| format!(" [{c}]")).unwrap_or_default();
                findings.push(Finding {
                    rule_id: format!("deps/{}@{}/{}", package.name, package.version, vuln.id),
                    title: format!(
                        "{} {} rentan terhadap {}{}",
                        package.name, package.version, vuln.id, cve
                    ),
                    severity: vuln.severity(),
                    source: Source::Rule,
                    file: lock_display.clone(),
                    line: 0,
                    snippet: String::new(),
                    message: vuln
                        .summary
                        .clone()
                        .or_else(|| vuln.details.clone())
                        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
                        .map(|s| s.chars().take(400).collect())
                        .unwrap_or_else(|| "tidak ada ringkasan".to_string()),
                });
            }
        }
    }

    let findings = rules::sorted_dedup(findings);
    let shown: Vec<Finding> = findings
        .iter()
        .filter(|f| f.severity >= args.min_severity.into())
        .cloned()
        .collect();

    report::print(&shown, args.format, 0)?;
    Ok(())
}
