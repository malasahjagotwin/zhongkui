//! Perintah `zhongkui audit`: pemindaian deterministik, lalu opsional diperkaya LLM.

use crate::cli::{AuditArgs, SourceFilter};
use crate::finding::{Finding, Severity, Source};
use crate::json;
use crate::llm::LlmClient;
use crate::report;
use crate::rules::{self, ScanOptions};
use anyhow::Result;
use serde::Deserialize;

/// Batas jumlah data yang dikirim ke pihak ketiga saat `--llm-discover`.
/// Sengaja konservatif: mengirim terlalu banyak kode ke relay luar adalah
/// keputusan yang sebaiknya disadari, bukan efek samping diam-diam.
const MAX_FILES_TO_LLM: usize = 20;
const MAX_FILE_BYTES_TO_LLM: usize = 40_000;
const MAX_TOTAL_BYTES_TO_LLM: usize = 300_000;
/// Temuan per panggilan triage — menjaga prompt tetap fokus.
const FINDINGS_PER_BATCH: usize = 12;

const TRIAGE_SYSTEM: &str = "\
Kamu auditor keamanan aplikasi yang teliti dan konservatif.
Tugasmu menilai temuan otomatis: apakah positif palsu, dan seberapa berat sebenarnya.
Aturan:
- Balas HANYA dengan JSON array. Tanpa penjelasan di luar array, tanpa pagar markdown.
- Jangan mengarang temuan baru; nilai hanya yang diberikan.
- Kalau bukti tidak cukup untuk memutuskan, pakai verdict \"uncertain\" — jangan asal hapus.
- severity hanya boleh: info, low, medium, high, critical.
Format tiap elemen: {\"index\": <int>, \"verdict\": \"true_positive\"|\"false_positive\"|\"uncertain\", \"severity\": \"<level>\", \"reason\": \"<alasan singkat>\", \"remediation\": \"<langkah perbaikan singkat>\"}";

const DISCOVER_SYSTEM: &str = "\
Kamu auditor keamanan aplikasi. Temukan kerentanan pada kode yang diberikan.
Fokus pada hal yang benar-benar ada di kode: injeksi, masalah otorisasi, kebocoran data,
kriptografi lemah, penanganan input tidak aman, race condition, dan rahasia hardcoded.
Aturan:
- Balas HANYA dengan JSON array. Tanpa penjelasan di luar array, tanpa pagar markdown.
- Jangan laporkan hal yang bersifat gaya penulisan atau preferensi.
- Kalau tidak menemukan apa pun, balas array kosong: []
- severity hanya boleh: info, low, medium, high, critical.
- Sertakan nomor baris yang akurat sesuai kode masukan.
- Jangan sertakan nilai rahasia apa pun secara utuh di dalam laporan.
Format tiap elemen: {\"rule_id\": \"llm/<slug>\", \"title\": \"<judul>\", \"severity\": \"<level>\", \"line\": <int>, \"snippet\": \"<potongan kode>\", \"message\": \"<penjelasan dan perbaikan>\"}";

#[derive(Deserialize)]
struct TriageItem {
    index: usize,
    verdict: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
}

#[derive(Deserialize)]
struct DiscoverItem {
    #[serde(default)]
    rule_id: Option<String>,
    title: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    line: Option<usize>,
    #[serde(default)]
    snippet: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub async fn run(args: AuditArgs) -> Result<()> {
    let scan_opts = ScanOptions {
        respect_ignore: !args.no_ignore,
    };

    eprintln!("→ memindai {}", args.path.display());
    let findings = rules::scan(&args.path, &scan_opts)?;
    eprintln!(
        "  {} temuan dari rule deterministik ({} file)",
        findings.len(),
        findings.iter().map(|f| &f.file).collect::<std::collections::BTreeSet<_>>().len()
    );

    let mut findings = findings;
    let mut rejected = 0usize;

    if args.llm || args.llm_discover {
        let client = LlmClient::from_env(args.model.clone())?;
        eprintln!(
            "→ mode LLM: model `{}` via {}",
            client.model(),
            client.base_url()
        );
        eprintln!("  PERHATIAN: isi source code akan dikirim ke endpoint tersebut.");

        if args.llm {
            let before = findings.len();
            findings = triage(&client, findings).await?;
            rejected = before.saturating_sub(findings.len());
        }

        if args.llm_discover {
            let discovered = discover(&client, &args.path, &scan_opts, &findings).await?;
            eprintln!("  {} temuan tambahan dari analisis LLM", discovered.len());
            findings.extend(discovered);
        }
    }

    findings = rules::sorted_dedup(findings);

    let shown: Vec<Finding> = findings
        .iter()
        .filter(|f| f.severity >= args.min_severity.into())
        .filter(|f| match args.source {
            SourceFilter::All => true,
            SourceFilter::Rule => f.source == Source::Rule,
            SourceFilter::Llm => f.source == Source::Llm,
        })
        .cloned()
        .collect();

    report::print(&shown, args.format, rejected)?;
    Ok(())
}

/// Minta model menilai temuan deterministik: positif palsu atau bukan, dan
/// seberapa berat sebenarnya.
async fn triage(client: &LlmClient, findings: Vec<Finding>) -> Result<Vec<Finding>> {
    if findings.is_empty() {
        return Ok(findings);
    }

    let batches: Vec<Vec<Finding>> = findings.chunks(FINDINGS_PER_BATCH).map(<[Finding]>::to_vec).collect();
    let total = batches.len();
    let mut result = Vec::with_capacity(findings.len());

    for (i, batch) in batches.into_iter().enumerate() {
        eprintln!("→ triage LLM {}/{} ({} temuan)", i + 1, total, batch.len());

        let payload = serde_json::json!(
            batch
                .iter()
                .enumerate()
                .map(|(idx, f)| serde_json::json!({
                    "index": idx,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity.label().to_ascii_lowercase(),
                    "snippet": f.snippet,
                    "message": f.message,
                }))
                .collect::<Vec<_>>()
        );

        let user = format!(
            "Triage temuan keamanan berikut. Balas HANYA JSON array.\n\nTemuan:\n{}",
            serde_json::to_string_pretty(&payload)?
        );

        let raw = client.chat(TRIAGE_SYSTEM, &user).await?;

        // Kegagalan parsing tidak boleh membatalkan seluruh audit — kalau model
        // menjawab ngawur, temuan asli tetap dipertahankan apa adanya.
        let items: Vec<TriageItem> = match json::extract_array(&raw) {
            Ok(items) => items,
            Err(e) => {
                eprintln!("  ! triage dilewati untuk batch ini: {e}");
                result.extend(batch);
                continue;
            }
        };

        let by_index: std::collections::HashMap<usize, TriageItem> =
            items.into_iter().map(|it| (it.index, it)).collect();

        for (idx, mut finding) in batch.into_iter().enumerate() {
            let Some(item) = by_index.get(&idx) else {
                result.push(finding);
                continue;
            };

            if item.verdict.eq_ignore_ascii_case("false_positive") {
                // Dilaporkan sebagai count, bukan dibuang diam-diam, supaya
                // keputusan model tetap bisa diaudit.
                continue;
            }

            if let Some(sev) = item.severity.as_deref().and_then(Severity::parse_loose) {
                finding.severity = sev;
            }
            if let Some(reason) = &item.reason {
                finding.message = format!("{} [LLM: {}]", finding.message, reason.trim());
            }
            if let Some(fix) = &item.remediation {
                finding.message = format!("{} Perbaikan: {}", finding.message, fix.trim());
            }
            result.push(finding);
        }
    }

    Ok(result)
}

/// Kirim isi file ke model untuk mencari hal yang lolos dari regex.
async fn discover(
    client: &LlmClient,
    root: &std::path::Path,
    opts: &ScanOptions,
    known: &[Finding],
) -> Result<Vec<Finding>> {
    let files = rules::collect_files(root, opts)?;

    // File yang sudah punya temuan rule diprioritaskan — biasanya di situ
    // masalahnya memang ada.
    let flagged: std::collections::BTreeSet<&str> = known.iter().map(|f| f.file.as_str()).collect();

    let mut candidates: Vec<std::path::PathBuf> = files
        .into_iter()
        .filter(|p| {
            std::fs::metadata(p)
                .map(|m| m.len() as usize <= MAX_FILE_BYTES_TO_LLM)
                .unwrap_or(false)
        })
        .collect();

    candidates.sort_by_key(|p| {
        let rel = p
            .strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/");
        !flagged.contains(rel.as_str()) // yang sudah ditandai duluan
    });

    let mut out = Vec::new();
    let mut total_bytes = 0usize;

    for (i, path) in candidates.iter().take(MAX_FILES_TO_LLM).enumerate() {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if total_bytes + content.len() > MAX_TOTAL_BYTES_TO_LLM {
            eprintln!("  ! batas total {} byte tercapai, sisa file dilewati", MAX_TOTAL_BYTES_TO_LLM);
            break;
        }
        total_bytes += content.len();

        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        eprintln!("→ analisis LLM {}/{}: {}", i + 1, MAX_FILES_TO_LLM.min(candidates.len()), rel);

        let user = format!(
            "Audit file `{rel}` berikut. Balas HANYA JSON array sesuai format.\n\n```\n{content}\n```"
        );

        let raw = match client.chat(DISCOVER_SYSTEM, &user).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ! file dilewati: {e}");
                continue;
            }
        };

        let items: Vec<DiscoverItem> = match json::extract_array(&raw) {
            Ok(items) => items,
            Err(e) => {
                eprintln!("  ! keluaran tidak bisa diparse: {e}");
                continue;
            }
        };

        for item in items {
            let title = item.title.trim().to_string();
            if title.is_empty() {
                continue;
            }
            out.push(Finding {
                rule_id: item
                    .rule_id
                    .filter(|r| !r.trim().is_empty())
                    .unwrap_or_else(|| "llm/discovery".to_string()),
                title,
                severity: item
                    .severity
                    .as_deref()
                    .and_then(Severity::parse_loose)
                    .unwrap_or(Severity::Medium),
                source: Source::Llm,
                file: rel.clone(),
                line: item.line.unwrap_or(0),
                snippet: item.snippet.unwrap_or_default().trim().chars().take(200).collect(),
                message: item.message.unwrap_or_default().trim().to_string(),
            });
        }
    }

    Ok(out)
}
