//! Deteksi kredensial hardcoded.
//!
//! Semua regex di sini punya capture group 1 yang menunjuk tepat ke nilai
//! rahasianya, bukan ke seluruh baris — itu yang dipakai `redact_line` untuk
//! menyensor nilai sebelum masuk laporan.

use crate::finding::{redact_line, Finding, Severity, Source};
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
            r#"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']([^"'\s]{12,})["']"#
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
    let distinct = lower.chars().collect::<std::collections::BTreeSet<_>>().len();
    distinct < 6
}

/// Scan satu baris; tambahkan temuan ke `out`.
pub fn scan_line(rel_path: &str, lineno: usize, line: &str, out: &mut Vec<Finding>) {
    // Baris panjang (mis. bundle/minified) bikin snippet nggak ada gunanya.
    if line.len() > 4_000 {
        return;
    }

    for rule in RULES.iter() {
        let (redacted, secret) = redact_line(line, &rule.re);
        let Some(secret) = secret else { continue };

        if is_placeholder(&secret) {
            continue;
        }

        out.push(Finding {
            rule_id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            source: Source::Rule,
            file: rel_path.to_string(),
            line: lineno,
            snippet: redacted.trim().chars().take(200).collect(),
            message: format!(
                "Kredensial terdeteksi ({} karakter, diredaksi). Pindahkan ke secret manager / env var dan rotasi nilainya.",
                secret.chars().count()
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
            found.iter().any(|f| f.rule_id == "secret/generic-assignment"),
            "password pada assignment tidak terdeteksi: {found:?}"
        );
    }

    #[test]
    fn ignores_short_values() {
        // Di bawah ambang panjang, terlalu berisik untuk dilaporkan.
        let found = scan(r#"password = "abc""#);
        assert!(found.is_empty(), "nilai pendek seharusnya diabaikan");
    }
}
