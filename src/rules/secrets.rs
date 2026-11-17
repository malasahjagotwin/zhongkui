//! Deteksi kredensial hardcoded.
//!
//! Semua regex di sini punya capture group 1 yang menunjuk tepat ke nilai
//! rahasianya, bukan ke seluruh baris — itu yang dipakai `redact_line` untuk
//! menyensor nilai sebelum masuk laporan.

use crate::finding::{Finding, Severity, Source, redact_line, sanitize_display};
use regex::Regex;
use std::sync::LazyLock;

pub struct SecretRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub re: Regex,
}

macro_rules! rule {
    ($id:literal, $title:literal, $sev:expr, $pat:literal) => {
        SecretRule {
            id: $id,
            title: $title,
            severity: $sev,
            re: Regex::new($pat).expect("regex secret tidak valid"),
        }
    };
}

pub static RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    vec![
        rule!(
            "secret/private-key",
            "Private key tertanam di source",
            Severity::Critical,
            r"(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----)"
        ),
        rule!(
            "secret/aws-access-key",
            "AWS access key ID",
            Severity::Critical,
            r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"
        ),
        rule!(
            "secret/github-token",
            "GitHub token",
            Severity::Critical,
            r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"
        ),
        rule!(
            "secret/github-pat-fine-grained",
            "GitHub fine-grained PAT",
            Severity::Critical,
            r"\b(github_pat_[A-Za-z0-9_]{60,})\b"
        ),
        rule!(
            "secret/openai-style-key",
            "API key bergaya OpenAI (sk-...)",
            Severity::Critical,
            r"\b(sk-[A-Za-z0-9_\-]{20,})\b"
        ),
        rule!(
            "secret/stripe-live-key",
            "Stripe live secret key",
            Severity::Critical,
            r"\b(sk_live_[A-Za-z0-9]{20,})\b"
        ),
        rule!(
            "secret/slack-token",
            "Slack token",
            Severity::Critical,
            r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"
        ),
        rule!(
            "secret/slack-webhook",
            "Slack incoming webhook URL",
            Severity::High,
            r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,})"
        ),
        rule!(
            "secret/google-api-key",
            "Google API key",
            Severity::High,
            r"\b(AIza[0-9A-Za-z_\-]{35})\b"
        ),
        rule!(
            "secret/twilio-account-sid",
            "Twilio account SID",
            Severity::High,
            r"\b(AC[0-9a-fA-F]{32})\b"
        ),
        rule!(
            "secret/sendgrid-key",
            "SendGrid API key",
            Severity::High,
            r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"
        ),
        rule!(
            "secret/jwt",
            "JSON Web Token tertanam",
            Severity::Medium,
            r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"
        ),
        rule!(
            "secret/generic-assignment",
            "Nilai rahasia pada assignment",
            Severity::Medium,
            r#"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|passwd|password|access[_-]?token|auth[_-]?token|token|private[_-]?key)\s*[:=]\s*["']([^"'\s]{12,})["']"#
        ),
        // Baris gaya `.env` / `.properties` tanpa tanda kutip:
        //   DB_PASSWORD=Tr0ub4dor3xKp9mn
        // Tanpa rule ini, kredensial di berkas konfigurasi non-.env lolos
        // sepenuhnya, karena rule di atas mensyaratkan tanda kutip.
        rule!(
            "secret/unquoted-assignment",
            "Nilai rahasia tanpa tanda kutip",
            Severity::Medium,
            r"(?im)^\s*(?:export\s+)?[A-Za-z0-9_]*(?:API[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE[_-]?KEY)[A-Za-z0-9_]*\s*=\s*([A-Za-z0-9_\-+/.=]{16,})"
        ),
    ]
});

/// Nilai yang jelas-jelas bukan rahasia nyata: placeholder, contoh, dummy.
///
/// Tanpa filter ini rule `generic-assignment` akan berisik sekali di file
/// konfigurasi dan dokumentasi, dan berisik = diabaikan orang.
fn is_placeholder(value: &str) -> bool {
    const MARKERS: &[&str] = &[
        "example",
        "sample",
        "dummy",
        "placeholder",
        "changeme",
        "change_me",
        "your_",
        "your-",
        "redacted",
        "totally_fake",
        "not_a_real",
        "foobar",
        "lorem",
        "<",
        ">",
        "${",
        "{{",
        "}}",
        "%s",
        "xxx",
        "aaaa",
    ];

    let lower = value.to_ascii_lowercase();
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }

    // Entropi kasar: rahasia asli hampir selalu punya banyak karakter berbeda.
    let distinct = lower
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    distinct < 6
}

/// Terapkan **seluruh** rule redaksi ke satu baris.
///
/// Dipakai untuk membentuk snippet laporan. Penting: snippet tidak boleh hanya
/// diredaksi oleh rule yang sedang menghasilkan temuan. Baris seperti
/// `{"aws":"AKIA...","gh":"ghp_..."}` akan dilaporkan dua kali, dan masing-
/// masing temuan harus menyembunyikan **kedua** nilai — kalau tidak, temuan
/// AWS membocorkan token GitHub di kolom snippet-nya.
pub fn redact_all(line: &str) -> String {
    let mut out = line.to_string();
    for rule in RULES.iter() {
        out = redact_line(&out, &rule.re).0;
    }
    out
}

/// Scan satu baris; tambahkan temuan ke `out`.
pub fn scan_line(rel_path: &str, lineno: usize, line: &str, out: &mut Vec<Finding>) {
    // Baris panjang (mis. bundle/minified) bikin snippet nggak ada gunanya.
    if line.len() > 4_000 {
        return;
    }

    // Kumpulkan dulu rule mana yang punya kecocokan nyata. Pemeriksaan
    // `is_match` murah; redaksi penuh (14 regex) baru dijalankan sekali dan
    // hanya kalau ada yang cocok — kalau tidak, mayoritas baris di sebuah repo
    // akan membayar biaya itu tanpa alasan.
    // (rule, nilai-nilai rahasia asli yang lolos filter placeholder)
    let mut hits: Vec<(&SecretRule, Vec<String>)> = Vec::new();

    for rule in RULES.iter() {
        if !rule.re.is_match(line) {
            continue;
        }

        let (_, matches) = redact_line(line, &rule.re);

        // Periksa SETIAP kecocokan, bukan hanya yang pertama. Kalau yang
        // pertama kebetulan placeholder, rahasia asli di belakangnya tetap
        // harus dilaporkan.
        let real: Vec<String> = matches
            .into_iter()
            .filter(|value| !value.is_empty() && !is_placeholder(value))
            .collect();

        if !real.is_empty() {
            hits.push((rule, real));
        }
    }

    if hits.is_empty() {
        return;
    }

    // Rule generik tidak perlu melapor untuk nilai yang sudah ditangkap rule
    // spesifik. Tanpa ini, `GITHUB_TOKEN = "ghp_..."` dilaporkan dua kali
    // (sekali oleh `secret/github-token`, sekali oleh `secret/generic-assignment`).
    // Salinan owned: `hits` akan di-`retain` (mutable) tepat setelah ini, jadi
    // set ini tidak boleh meminjam isinya.
    let specific_values: std::collections::BTreeSet<String> = hits
        .iter()
        .filter(|(rule, _)| {
            rule.id != "secret/generic-assignment" && rule.id != "secret/unquoted-assignment"
        })
        .flat_map(|(_, values)| values.iter().cloned())
        .collect();

    hits.retain(|(rule, values)| {
        if rule.id == "secret/generic-assignment" || rule.id == "secret/unquoted-assignment" {
            values.iter().any(|v| !specific_values.contains(v))
        } else {
            true
        }
    });

    if hits.is_empty() {
        return;
    }

    // Snippet diredaksi dengan SELURUH rule, bukan hanya rule yang melapor.
    let snippet: String = sanitize_display(
        &redact_all(line)
            .trim()
            .chars()
            .take(200)
            .collect::<String>(),
    );

    for (rule, values) in hits {
        let longest = values.iter().map(|v| v.chars().count()).max().unwrap_or(0);

        out.push(Finding {
            rule_id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            source: Source::Rule,
            file: rel_path.to_string(),
            line: lineno,
            snippet: snippet.clone(),
            message: format!(
                "Kredensial terdeteksi ({longest} karakter, diredaksi). Pindahkan ke secret manager / env var dan rotasi nilainya."
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(line: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_line("src/config.rs", 1, line, &mut out);
        out
    }

    #[test]
    fn detects_aws_access_key() {
        let found = scan(r#"let key = "AKIAABCDEFGHIJKLMNOP";"#);
        assert!(
            found.iter().any(|f| f.rule_id == "secret/aws-access-key"),
            "AWS key tidak terdeteksi: {found:?}"
        );
    }

    #[test]
    fn skips_obvious_placeholder() {
        // Nilai contoh dari dokumentasi AWS — ini justru sumber false positive
        // paling umum kalau filter placeholder tidak ada.
        let found = scan(r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#);
        assert!(
            found.is_empty(),
            "placeholder seharusnya dilewati, tapi dapat: {found:?}"
        );
    }

    #[test]
    fn never_prints_full_secret_in_snippet() {
        let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let found = scan(&format!("const T: &str = \"{token}\";"));
        assert!(!found.is_empty(), "token GitHub tidak terdeteksi");

        for f in &found {
            assert!(
                !f.snippet.contains(token),
                "snippet membocorkan nilai rahasia utuh: {}",
                f.snippet
            );
        }
    }

    #[test]
    fn detects_generic_password_assignment() {
        let found = scan(r#"password = "s3cr3tP@ssw0rd90""#);
        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "secret/generic-assignment"),
            "password pada assignment tidak terdeteksi: {found:?}"
        );
    }

    #[test]
    fn ignores_short_values() {
        // Di bawah ambang panjang, terlalu berisik untuk dilaporkan.
        let found = scan(r#"password = "abc""#);
        assert!(found.is_empty(), "nilai pendek seharusnya diabaikan");
    }

    /// Regresi: satu baris berisi dua jenis rahasia. Temuan untuk salah satu
    /// rule tidak boleh menyisakan rahasia milik rule lain di snippet-nya.
    #[test]
    fn snippet_redacts_secrets_from_other_rules() {
        let aws = "AKIAABCDEFGHIJKLMNOP";
        let gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let found = scan(&format!(r#"{{"aws":"{aws}","gh":"{gh}"}}"#));

        assert!(
            found.len() >= 2,
            "kedua rahasia harus terdeteksi: {found:?}"
        );

        for f in &found {
            assert!(
                !f.snippet.contains(aws),
                "snippet temuan `{}` membocorkan AWS key: {}",
                f.rule_id,
                f.snippet
            );
            assert!(
                !f.snippet.contains(gh),
                "snippet temuan `{}` membocorkan GitHub token: {}",
                f.rule_id,
                f.snippet
            );
        }
    }

    /// Regresi: placeholder yang muncul lebih dulu tidak boleh menutupi
    /// rahasia asli yang ada setelahnya pada baris yang sama.
    #[test]
    fn placeholder_earlier_on_line_does_not_hide_real_secret() {
        let real = "Pr0dS3cr3tValue99Xq";
        let found = scan(&format!(
            r#"api_key = "your_api_key_here"; secret = "{real}""#
        ));

        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "secret/generic-assignment"),
            "rahasia asli tertutup oleh placeholder sebelumnya: {found:?}"
        );
    }

    #[test]
    fn detects_unquoted_env_style_assignment() {
        let found = scan("DB_PASSWORD=Tr0ub4dor3xKp9mn");
        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "secret/unquoted-assignment"),
            "assignment tanpa tanda kutip tidak terdeteksi: {found:?}"
        );
    }

    #[test]
    fn snippet_is_free_of_control_characters() {
        let found = scan("password = \"s3cr3tP@ssw0rd90\"\u{1b}[2J");
        for f in &found {
            assert!(
                !f.snippet.contains('\u{1b}'),
                "snippet masih memuat escape sequence: {:?}",
                f.snippet
            );
        }
    }

    /// Rule generik tidak boleh melaporkan nilai yang sudah ditangkap rule
    /// spesifik — satu kredensial cukup dilaporkan sekali.
    #[test]
    fn specific_rule_suppresses_generic_duplicate() {
        let found = scan(r#"GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz""#);
        let ids: Vec<&str> = found.iter().map(|f| f.rule_id.as_str()).collect();

        assert!(
            ids.contains(&"secret/github-token"),
            "rule spesifik harus melapor: {ids:?}"
        );
        assert!(
            !ids.contains(&"secret/generic-assignment"),
            "generic tidak boleh menduplikasi rule spesifik: {ids:?}"
        );
    }

    /// Kebalikannya: kalau rule spesifik tidak mengenali formatnya, rule
    /// generik tetap harus melapor.
    #[test]
    fn generic_rule_still_fires_when_no_specific_rule_matches() {
        let found = scan(r#"api_key = "Zq7Xk2mQ9pLw4nRt8vBc""#);
        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "secret/generic-assignment"),
            "generic harus tetap melapor: {found:?}"
        );
    }
}
