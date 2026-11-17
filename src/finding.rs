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
    /// Kunci dedup.
    ///
    /// `title` ikut disertakan, bukan hanya `(rule_id, file, line)`: temuan
    /// dari LLM sering tidak punya rule_id spesifik sehingga jatuh ke
    /// `llm/discovery` dengan line 0, dan tanpa `title` dua masalah berbeda
    /// pada berkas yang sama akan menyatu jadi satu dan salah satunya hilang.
    pub fn dedup_key(&self) -> (String, String, usize, String) {
        (
            self.rule_id.clone(),
            self.file.clone(),
            self.line,
            self.title.clone(),
        )
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
    format!("{head}...{tail}")
}

/// Redaksi **semua** kecocokan `pattern` pada baris.
///
/// Mengembalikan `(baris_teredaksi, daftar_nilai_cocok)`. Daftar berisi setiap
/// kecocokan, bukan hanya yang pertama: pemanggil perlu memeriksa tiap nilai
/// (placeholder atau bukan) sendiri. Versi sebelumnya hanya mengembalikan
/// kecocokan pertama, sehingga satu nilai placeholder di awal baris membuat
/// rahasia asli di belakangnya tidak pernah diperiksa.
///
/// Asumsi: kalau regex punya capture group 1, itu nilai rahasianya; kalau
/// tidak, seluruh kecocokan dianggap rahasia.
pub fn redact_line(line: &str, pattern: &regex::Regex) -> (String, Vec<String>) {
    let mut found: Vec<String> = Vec::new();

    let out = pattern
        .replace_all(line, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let secret = caps.get(1).map(|m| m.as_str()).unwrap_or(whole);

            if secret.is_empty() {
                return whole.to_string();
            }
            found.push(secret.to_string());
            // `replace` mengganti semua kemunculan nilai yang sama di dalam
            // kecocokan; itu yang diinginkan.
            whole.replace(secret, &redact(secret))
        })
        .into_owned();

    (out, found)
}

/// Netralkan karakter kontrol sebelum dicetak ke terminal.
///
/// Snippet berasal dari berkas yang tidak dipercaya. Escape sequence ANSI di
/// dalamnya bisa membersihkan layar lalu mencetak teks palsu di atas temuan
/// asli — penyerang cukup menaruh `\x1b[2J` di dalam komentar. Baris baru dan
/// tab dibiarkan karena keduanya tidak mengeksekusi apa pun.
pub fn sanitize_display(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
