//! Penyajian hasil.

use crate::cli::OutputFormat;
use crate::finding::{Finding, Severity};
use anyhow::Result;
use colored::Colorize;
use std::collections::BTreeMap;

pub fn print(findings: &[Finding], format: OutputFormat, rejected: usize) -> Result<()> {
    match format {
        OutputFormat::Text => print_text(findings, rejected),
        OutputFormat::Json => print_json(findings, rejected)?,
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

fn print_text(findings: &[Finding], rejected: usize) {
    if findings.is_empty() {
        println!("{}", "Tidak ada temuan.".green().bold());
        if rejected > 0 {
            println!(
                "{}",
                format!("({rejected} temuan ditolak LLM sebagai false positive)").bright_black()
            );
        }
        return;
    }

    for f in findings {
        let badge = format!("{:>8}", f.severity.label()).color(f.severity.color()).bold();
        let location = if f.line == 0 {
            f.file.clone()
        } else {
            format!("{}:{}", f.file, f.line)
        };

        println!("{badge}  {}", f.title.bold());
        println!("          {}  {}", location.bright_cyan(), f.rule_id.bright_black());
        println!(
            "          {}",
            format!("sumber: {}", f.source.label()).bright_black()
        );
        if !f.snippet.is_empty() {
            println!("          {}", f.snippet.dimmed());
        }
        if !f.message.is_empty() {
            for line in wrap(&f.message, 96) {
                println!("          {line}");
            }
        }
        println!();
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
    .filter_map(|s| c.get(s).map(|n| format!("{} {}", n, s.label().to_ascii_lowercase())))
    .collect();

    println!(
        "▸ {} temuan: {}",
        findings.len().to_string().bold(),
        parts.join(", ")
    );
    if rejected > 0 {
        println!(
            "▸ {} ditolak LLM sebagai false positive",
            rejected.to_string().bold()
        );
    }
}

fn print_json(findings: &[Finding], rejected: usize) -> Result<()> {
    let c = counts(findings);
    let summary = serde_json::json!({
        "total": findings.len(),
        "rejected_by_llm": rejected,
        "by_severity": {
            "critical": c.get(&Severity::Critical).copied().unwrap_or(0),
            "high": c.get(&Severity::High).copied().unwrap_or(0),
            "medium": c.get(&Severity::Medium).copied().unwrap_or(0),
            "low": c.get(&Severity::Low).copied().unwrap_or(0),
            "info": c.get(&Severity::Info).copied().unwrap_or(0),
        },
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
            f.message.replace('\n', " ")
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
