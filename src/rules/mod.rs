//! Rule engine deterministik.
//!
//! Bagian ini sengaja tidak menyentuh jaringan sama sekali. Semua temuan di
//! sini bisa direproduksi persis dengan input yang sama, jadi aman dipakai di
//! CI dan tidak membocorkan kode ke pihak ketiga.

pub mod patterns;
pub mod secrets;

use crate::finding::{Finding, Severity, Source};
use anyhow::{Context, Result};
use ignore::WalkBuilder;
use std::path::Path;

/// File lebih besar dari ini dilewati — biasanya hasil build atau bundle.
const MAX_FILE_BYTES: u64 = 1_500_000;

/// Ekstensi yang dipindai. Sengaja allowlist, bukan blocklist: lebih mudah
/// dipertanggungjawabkan dan menghindari membaca file biner raksasa.
const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "go", "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "kt", "kts", "rb", "php",
    "c", "h", "cc", "cpp", "cxx", "hpp", "cs", "swift", "scala", "lua", "pl", "sh", "bash", "zsh",
    "sql", "yaml", "yml", "toml", "json", "json5", "ini", "cfg", "conf", "env", "tf", "tfvars",
    "gradle", "xml", "properties", "graphql", "proto", "vue", "svelte", "html", "htm", "md", "txt",
];

/// Nama file tanpa ekstensi yang tetap harus dipindai.
const TEXT_FILENAMES: &[&str] = &["dockerfile", "makefile", "rakefile", "gemfile", "procfile"];

/// Direktori yang selalu dilewati, apa pun pengaturannya.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    ".terraform",
];

pub struct ScanOptions {
    /// Hormati .gitignore/.ignore. Dimatikan oleh `--no-ignore`.
    pub respect_ignore: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            respect_ignore: true,
        }
    }
}

/// File yang namanya sendiri sudah menandakan isi sensitif.
fn sensitive_filename(name: &str) -> Option<(&'static str, Severity, &'static str)> {
    let lower = name.to_ascii_lowercase();

    const EXACT: &[(&str, &str, Severity, &str)] = &[
        (".env", "secret/env-file", Severity::High, "File .env biasanya memuat kredensial. Pastikan tidak ikut ter-commit."),
        (".netrc", "secret/netrc", Severity::High, "File .netrc memuat kredensial login."),
        (".npmrc", "secret/npmrc", Severity::Medium, "File .npmrc bisa memuat auth token registry."),
        (".pgpass", "secret/pgpass", Severity::High, "File .pgpass memuat password PostgreSQL."),
        ("id_rsa", "secret/ssh-private-key", Severity::Critical, "SSH private key."),
        ("id_ed25519", "secret/ssh-private-key", Severity::Critical, "SSH private key."),
        ("id_ecdsa", "secret/ssh-private-key", Severity::Critical, "SSH private key."),
        ("id_dsa", "secret/ssh-private-key", Severity::Critical, "SSH private key."),
        ("credentials", "secret/credentials-file", Severity::High, "File kredensial AWS/gcloud."),
        ("keystore.jks", "secret/java-keystore", Severity::High, "Java keystore."),
    ];

    for (pat, id, sev, msg) in EXACT {
        if lower == *pat {
            return Some((id, *sev, msg));
        }
    }

    // .env.local, .env.production, dst.
    if let Some(suffix) = lower.strip_prefix(".env.") {
        // Template tidak memuat nilai nyata — menandainya cuma menghasilkan
        // kebisingan dan bikin temuan yang benar ikut diabaikan.
        const TEMPLATE_SUFFIXES: &[&str] = &["example", "sample", "template", "dist", "defaults"];
        if TEMPLATE_SUFFIXES.contains(&suffix) {
            return None;
        }
        return Some((
            "secret/env-file",
            Severity::High,
            "File .env.* biasanya memuat kredensial. Pastikan tidak ikut ter-commit.",
        ));
    }

    for ext in [".pem", ".p12", ".pfx", ".jks", ".keystore"] {
        if lower.ends_with(ext) {
            return Some((
                "secret/key-material",
                Severity::High,
                "Material kunci/privat terdeteksi. Kalau ini kunci produksi, rotasi segera.",
            ));
        }
    }

    // .key dan .crt tidak selalu privat, jadi jangan seagresif .pem.
    if lower.ends_with(".key") {
        return Some((
            "secret/key-material",
            Severity::Medium,
            "File .key perlu dicek manual: bisa kunci privat atau cuma kunci publik.",
        ));
    }

    None
}

fn extension_of(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_scannable(path: &Path) -> bool {
    let ext = extension_of(path);
    if TEXT_EXTENSIONS.contains(&ext.as_str()) {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    TEXT_FILENAMES.contains(&name.as_str()) || sensitive_filename(&name).is_some()
}

/// Baca dan pindai satu file. Mengembalikan jumlah baris yang dipindai.
fn scan_file(root: &Path, path: &Path, out: &mut Vec<Finding>) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("gagal membaca metadata {}", path.display()))?;
    if meta.len() > MAX_FILE_BYTES || !meta.is_file() {
        return Ok(());
    }

    let bytes = std::fs::read(path).with_context(|| format!("gagal membaca {}", path.display()))?;

    // Heuristik file biner: ada byte NUL di awal file.
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return Ok(());
    }

    let Ok(text) = String::from_utf8(bytes) else {
        return Ok(()); // bukan UTF-8, lewati
    };

    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if let Some((id, severity, message)) = sensitive_filename(name) {
            out.push(Finding {
                rule_id: id.to_string(),
                title: format!("File sensitif: {name}"),
                severity,
                source: Source::Rule,
                file: rel.clone(),
                line: 0,
                snippet: String::new(),
                message: message.to_string(),
            });
        }
    }

    let ext = extension_of(path);
    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        secrets::scan_line(&rel, lineno, line, out);
        patterns::scan_line(&rel, &ext, lineno, line, out);
    }

    Ok(())
}

/// Kumpulkan file yang layak dipindai, tanpa membaca isinya.
///
/// Dipakai `audit` untuk menentukan file mana yang dikirim ke LLM.
pub fn collect_files(root: &Path, opts: &ScanOptions) -> Result<Vec<std::path::PathBuf>> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // ikutkan file tersembunyi: .env justru sering jadi temuan
        .git_ignore(opts.respect_ignore)
        .git_global(opts.respect_ignore)
        .git_exclude(opts.respect_ignore)
        .ignore(opts.respect_ignore)
        .parents(opts.respect_ignore);

    builder.filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        !SKIP_DIRS.contains(&name.as_str())
    });

    let mut files = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue, // permission error dsb: lanjut saja
        };
        if entry.file_type().is_some_and(|t| t.is_file()) && is_scannable(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

/// Jalankan semua rule deterministik terhadap `root` (file atau direktori).
pub fn scan(root: &Path, opts: &ScanOptions) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let base = if root.is_file() {
        root.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        root.to_path_buf()
    };

    for path in collect_files(root, opts)? {
        // Error pada satu file tidak boleh membatalkan seluruh scan.
        let _ = scan_file(&base, &path, &mut findings);
    }

    Ok(sorted_dedup(findings))
}

/// Buang duplikat, urutkan dari yang paling berat.
pub fn sorted_dedup(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    findings.dedup_by(|a, b| a.dedup_key() == b.dedup_key());
    findings
}
