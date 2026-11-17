//! Heuristik pola kode berbahaya.
//!
//! Ini semua **petunjuk, bukan bukti**. Regex nggak bisa membedakan
//! `Command::new("ls")` dari `Command::new(user_input)`. Karena itu severity-nya
//! dijaga konservatif dan tiap temuan menyertakan alasan kenapa dicurigai.

use crate::finding::{Finding, Severity, Source, sanitize_display};
use regex::Regex;
use std::sync::LazyLock;

struct PatternRule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    re: Regex,
    message: &'static str,
    /// Kalau diset, rule cuma jalan untuk ekstensi ini.
    only_ext: Option<&'static [&'static str]>,
}

macro_rules! rule {
    ($id:literal, $title:literal, $sev:expr, $pat:literal, $msg:literal) => {
        PatternRule {
            id: $id,
            title: $title,
            severity: $sev,
            re: Regex::new($pat).expect("regex pattern tidak valid"),
            message: $msg,
            only_ext: None,
        }
    };
    ($id:literal, $title:literal, $sev:expr, $pat:literal, $msg:literal, $ext:expr) => {
        PatternRule {
            id: $id,
            title: $title,
            severity: $sev,
            re: Regex::new($pat).expect("regex pattern tidak valid"),
            message: $msg,
            only_ext: Some($ext),
        }
    };
}

static RULES: LazyLock<Vec<PatternRule>> = LazyLock::new(|| {
    vec![
        rule!(
            "pattern/tls-verify-disabled",
            "Verifikasi sertifikat TLS dimatikan",
            Severity::High,
            r"(?i)(danger_accept_invalid_certs|accept_invalid_hostnames|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false))",
            "Koneksi jadi rentan MITM. Kalau ini cuma untuk dev lokal, batasi ke konfigurasi dev dan jangan ikut ke build produksi."
        ),
        rule!(
            "pattern/shell-exec",
            "Eksekusi shell dengan input dinamis",
            Severity::High,
            r"(?i)(os\.system\s*\(|subprocess\.(?:run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True|child_process\.(?:exec|execSync)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()",
            "Kalau argumennya berasal dari input pengguna, ini command injection. Pakai API tanpa shell dan argumen berbentuk list/array."
        ),
        rule!(
            "pattern/eval",
            "Penggunaan eval / eksekusi kode dinamis",
            Severity::High,
            r"(?i)\b(eval|exec)\s*\(",
            "Eksekusi kode dari string hampir selalu bisa dihindari. Kalau inputnya bisa dikendalikan penyerang, ini RCE."
        ),
        rule!(
            "pattern/sql-string-concat",
            "Query SQL disusun lewat konkatenasi string",
            Severity::Medium,
            r#"(?i)\b(?:select|insert\s+into|update|delete\s+from)\b[^\n]{0,200}?(?:\+\s*[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]+\}|format!\s*\(|\.format\s*\(|%\s*\(|\bconcat\s*\()"#,
            "Pola khas SQL injection. Pakai prepared statement / parameter binding."
        ),
        rule!(
            "pattern/weak-hash",
            "Algoritma hash lemah",
            Severity::Medium,
            // Perhatikan `r#"..."#`: raw string biasa tidak bisa memuat tanda
            // kutip, jadi regex yang perlu mencocokkan kutip wajib pakai ini.
            r#"(?i)(?:\bmd5\s*\(|\bsha1\s*\(|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']|\bMd5::|\bSha1::)"#,
            "MD5/SHA-1 tidak layak untuk password atau integritas data yang perlu tahan tabrakan. Pakai Argon2/bcrypt untuk password, SHA-256+ untuk integritas."
        ),
        rule!(
            "pattern/insecure-random",
            "Random non-kriptografis untuk nilai sensitif",
            Severity::Medium,
            r"(?i)(Math\.random\s*\(\)|rand\.randint\s*\(|random\.random\s*\(\)|rand::random\s*\(\)|srand\s*\()",
            "Kalau dipakai untuk token/session ID, PRNG ini bisa diprediksi. Pakai CSPRNG (secrets, crypto.randomBytes, OsRng)."
        ),
        rule!(
            "pattern/debug-enabled",
            "Mode debug aktif",
            Severity::Low,
            r"(?i)(\bDEBUG\s*=\s*True|\bdebug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True)",
            "Mode debug membocorkan stack trace dan bisa mengaktifkan endpoint diagnostik. Pastikan mati di produksi."
        ),
        rule!(
            "pattern/auth-todo",
            "Catatan TODO/FIXME di sekitar logika auth",
            Severity::Low,
            r"(?i)(?:TODO|FIXME|HACK|XXX)[^\n]{0,80}(?:auth|login|permission|acl|token|validate|sanitiz)",
            "Penanda ini sering menandai kontrol keamanan yang belum selesai. Verifikasi manual."
        ),
        rule!(
            "pattern/unsafe-block",
            "Blok unsafe",
            Severity::Low,
            r"\bunsafe\s*\{",
            "Blok unsafe memindahkan jaminan memori ke penulis kode. Pastikan invariant-nya didokumentasikan dan diuji.",
            &["rs"]
        ),
    ]
});

pub fn scan_line(rel_path: &str, ext: &str, lineno: usize, line: &str, out: &mut Vec<Finding>) {
    if line.len() > 4_000 {
        return;
    }

    // Snippet WAJIB lewat redaksi rahasia, walaupun rule ini bukan rule
    // kredensial. Contoh nyata: `# TODO: rotate this token ghp_...` cocok
    // dengan rule auth-todo, dan tanpa redaksi baris mentahnya — lengkap
    // dengan token — ikut tercetak ke laporan.
    //
    // Dihitung malas: hanya kalau memang ada rule yang cocok.
    let mut snippet: Option<String> = None;

    for rule in RULES.iter() {
        if let Some(allowed) = rule.only_ext
            && !allowed.contains(&ext)
        {
            continue;
        }

        let Some(m) = rule.re.find(line) else {
            continue;
        };

        let snippet = snippet
            .get_or_insert_with(|| {
                sanitize_display(
                    &super::secrets::redact_all(line)
                        .trim()
                        .chars()
                        .take(200)
                        .collect::<String>(),
                )
            })
            .clone();

        out.push(Finding {
            rule_id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            source: Source::Rule,
            file: rel_path.to_string(),
            line: lineno,
            snippet,
            message: format!("{} (kecocokan: `{}`)", rule.message, m.as_str()),
        });
    }
}
