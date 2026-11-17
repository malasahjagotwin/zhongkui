use serde::Serialize;
use std::fmt;

/// Tingkat keparahan temuan.
///
/// Urutan `Ord` sengaja dari paling ringan ke paling berat supaya filter
/// `min_severity` dan pengurutan hasil bisa pakai perbandingan langsung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Terima berbagai ejaan yang mungkin dipakai model: "HIGH", "high",
    /// "High", "critical ". Model tidak selalu konsisten soal kapitalisasi.
    pub fn parse_loose(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "note" => Some(Severity::Info),
            "low" | "minor" => Some(Severity::Low),
            "medium" | "moderate" | "med" => Some(Severity::Medium),
            "high" | "major" => Some(Severity::High),
            "critical" | "crit" | "severe" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Dipakai untuk pewarnaan terminal.
    pub fn color(self) -> colored::Color {
        use colored::Color;
        match self {
            Severity::Info => Color::BrightBlack,
            Severity::Low => Color::Cyan,
            Severity::Medium => Color::Yellow,
            Severity::High => Color::BrightRed,
            Severity::Critical => Color::Red,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Dari mana temuan berasal — ini penting untuk audit trail.
///
/// Temuan dari `Rule` deterministik dan bisa direproduksi; temuan dari `Llm`
/// probabilistik dan harus diverifikasi manual sebelum dilaporkan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Deteksi regex/pattern lokal, deterministik.
    Rule,
    /// Usulan model bahasa, perlu verifikasi manusia.
    Llm,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Rule => "rule",
            Source::Llm => "llm",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub source: Source,
    /// Path relatif terhadap root scan, supaya laporan bisa dipindah-pindah.
    pub file: String,
    pub line: usize,
    /// Potongan kode, sudah diredaksi kalau mengandung kredensial.
    pub snippet: String,
    pub message: String,
}

impl Finding {
    /// Kunci dedup. Temuan yang sama dari rule dan LLM dianggap satu.
    pub fn dedup_key(&self) -> (String, String, usize) {
        (self.rule_id.clone(), self.file.clone(), self.line)
    }
}

/// Sembunyikan nilai rahasia sebelum masuk laporan.
///
/// Laporan kerap di-paste ke issue tracker atau chat. Kalau snippet memuat
/// kredensial mentah, tool ini justru jadi jalur kebocoran baru.
pub fn redact(secret: &str) -> String {
    let n = secret.chars().count();
    if n <= 8 {
        return "*".repeat(n.max(3));
    }
    let head: String = secret.chars().take(4).collect();
    let tail: String = secret.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// Redaksi nilai rahasia di baris, dengan asumsi regex punya capture group
/// yang menunjuk tepat ke nilai rahasianya (bukan ke seluruh baris).
pub fn redact_line(line: &str, pattern: &regex::Regex) -> (String, Option<String>) {
    let mut found: Option<String> = None;
    let out = pattern
        .replace_all(line, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            // Group 1 kalau ada (nilai rahasianya), kalau tidak pakai match penuh.
            let secret = caps.get(1).map(|m| m.as_str()).unwrap_or(whole);
            if found.is_none() {
                found = Some(secret.to_string());
            }
            whole.replace(secret, &redact(secret))
        })
        .into_owned();
    (out, found)
}
