//! Penyajian hasil.

use crate::cli::OutputFormat;
use crate::finding::{Finding, Severity, sanitize_display};
use anyhow::Result;
use colored::Colorize;
use std::collections::BTreeMap;

/// Cetak hasil.
///
/// `rejected` = temuan yang dibuang LLM (false positive).
/// `hidden` = temuan yang ada tetapi tersaring oleh `--min-severity`/`--source`.
/// Keduanya dilaporkan supaya "tidak ada temuan" tidak pernah berarti
/// "kami menyembunyikan sesuatu".
pub fn print(
    findings: &[Finding],
    format: OutputFormat,
    rejected: usize,
    hidden: usize,
) -> Result<()> {
    match format {
        OutputFormat::Text => print_text(findings, rejected, hidden),
        OutputFormat::Json => print_json(findings, rejected, hidden)?,
        OutputFormat::Grep => print_grep(findings),
    }
    Ok(())
}

fn counts(findings: &[Finding]) -> BTreeMap<Severity, usize> {
    let mut map = BTreeMap::new();
    for f in findings {
        *map.entry(f.severity).or_insert(0) += 1;
    }
    map
}

fn counts_json(c: &BTreeMap<Severity, usize>) -> serde_json::Value {
    serde_json::json!({
        "critical": c.get(&Severity::Critical).copied().unwrap_or(0),
        "high": c.get(&Severity::High).copied().unwrap_or(0),
        "medium": c.get(&Severity::Medium).copied().unwrap_or(0),
        "low": c.get(&Severity::Low).copied().unwrap_or(0),
        "info": c.get(&Severity::Info).copied().unwrap_or(0),
    })
}

fn print_text(findings: &[Finding], rejected: usize, hidden: usize) {
    if findings.is_empty() {
        if hidden > 0 {
            // Ini yang sebelumnya menyesatkan: temuan ada, hanya tersaring,
            // tapi pesannya bilang "Tidak ada temuan."
            println!(
                "{}",
                format!("Tidak ada temuan yang ditampilkan — {hidden} temuan tersaring oleh --min-severity/--source.")
                    .yellow()
                    .bold()
            );
        } else {
            println!("{}", "Tidak ada temuan.".green().bold());
        }
        if rejected > 0 {
            println!(
                "{}",
                format!("({rejected} temuan ditolak LLM sebagai false positive)").bright_black()
            );
        }
        return;
    }

    // Kelompokkan per lokasi. Temuan rule dan LLM sering menunjuk baris yang
    // sama untuk masalah yang sama; menampilkannya sebagai dua blok terpisah
    // membuat laporan terasa berisi duplikat. Dikelompokkan, keduanya terbaca
    // sebagai satu lokasi dengan dua sumber — dan tidak ada informasi hilang.
    for (file, line, group) in group_by_location(findings) {
        let worst = group
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        let location = if line == 0 {
            file.clone()
        } else {
            format!("{file}:{line}")
        };

        let count_note = if group.len() > 1 {
            format!("  ({} temuan)", group.len())
                .bright_black()
                .to_string()
        } else {
            String::new()
        };

        println!(
            "{}  {}{count_note}",
            format!("{:>8}", worst.label()).color(worst.color()).bold(),
            location.bright_cyan()
        );

        for f in &group {
            println!(
                "          {}  {}  {}",
                f.title.bold(),
                f.rule_id.bright_black(),
                format!("[{}]", f.source.label()).bright_black()
            );

            // Snippet berasal dari berkas yang tidak dipercaya: escape ANSI di
            // dalamnya bisa membersihkan layar lalu mencetak "0 temuan" palsu.
            let snippet = sanitize_display(&f.snippet);
            if !snippet.is_empty() {
                println!("          {}", snippet.dimmed());
            }

            let message = sanitize_display(&f.message);
            if !message.is_empty() {
                for l in wrap(&message, 92) {
                    println!("          {l}");
                }
            }
            println!();
        }
    }

    let c = counts(findings);
    let parts: Vec<String> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .filter_map(|s| {
        c.get(s)
            .map(|n| format!("{} {}", n, s.label().to_ascii_lowercase()))
    })
    .collect();

    println!(
        "▸ {} temuan: {}",
        findings.len().to_string().bold(),
        parts.join(", ")
    );
    if hidden > 0 {
        println!(
            "▸ {} temuan tersaring oleh --min-severity/--source",
            hidden.to_string().bold()
        );
    }
    if rejected > 0 {
        println!(
            "▸ {} ditolak LLM sebagai false positive",
            rejected.to_string().bold()
        );
    }
}

/// Kelompokkan temuan berdasarkan `(file, line)`, menjaga urutan kemunculan.
fn group_by_location(findings: &[Finding]) -> Vec<(String, usize, Vec<&Finding>)> {
    let mut groups: Vec<(String, usize, Vec<&Finding>)> = Vec::new();
    for f in findings {
        match groups
            .iter_mut()
            .find(|(file, line, _)| *file == f.file && *line == f.line)
        {
            Some((_, _, members)) => members.push(f),
            None => groups.push((f.file.clone(), f.line, vec![f])),
        }
    }
    groups
}

fn print_json(findings: &[Finding], rejected: usize, hidden: usize) -> Result<()> {
    let c = counts(findings);
    let summary = serde_json::json!({
        "total": findings.len(),
        "hidden_by_filter": hidden,
        "rejected_by_llm": rejected,
        "by_severity": counts_json(&c),
    });

    let out = serde_json::json!({ "summary": summary, "findings": findings });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// `file:line:SEVERITY:rule:pesan` — satu baris per temuan, sengaja tanpa
/// pewarnaan supaya bisa di-pipe dan di-grep dengan aman.
fn print_grep(findings: &[Finding]) {
    for f in findings {
        println!(
            "{}:{}:{}:{}:{}",
            f.file,
            f.line,
            f.severity.label(),
            f.rule_id,
            sanitize_display(&f.message).replace('\n', " ")
        );
    }
}

/// Bungkus teks supaya tetap terbaca di terminal sempit.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
