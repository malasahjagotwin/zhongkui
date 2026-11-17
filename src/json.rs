//! Ekstraksi JSON dari keluaran model bahasa.
//!
//! Model sering membungkus JSON dengan pagar markdown, kalimat pembuka, atau
//! tanda kutip penutup. Parser yang kaku akan gagal di mayoritas respons
//! padahal isinya benar — jadi di sini kita ambil blok array pertama yang
//! seimbang dan parse itu.

use anyhow::{Context, Result};

/// Ambil dan parse array JSON pertama yang ditemukan di `raw`.
pub fn extract_array<T: serde::de::DeserializeOwned>(raw: &str) -> Result<Vec<T>> {
    let cleaned = strip_fences(raw);
    let slice = balanced_array(&cleaned)
        .with_context(|| format!("tidak menemukan array JSON pada keluaran model: {}", preview(raw)))?;

    let values: Vec<T> = serde_json::from_str(slice)
        .with_context(|| format!("array JSON tidak cocok dengan skema yang diharapkan: {}", preview(slice)))?;

    Ok(values)
}

/// Buang pagar kode markdown kalau ada.
fn strip_fences(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Cari `[` pertama lalu lacak kedalaman kurung untuk menemukan penutupnya,
/// dengan mengabaikan `[`/`]` yang berada di dalam string.
fn balanced_array(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let start = s.find('[')?;

    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, &b) in bytes[start..].iter().enumerate() {
        let idx = start + offset;

        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }

        match b {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=idx]);
                }
            }
            _ => {}
        }
    }

    None
}

fn preview(s: &str) -> String {
    let clean = s.trim().replace('\n', " ");
    if clean.chars().count() <= 200 {
        clean
    } else {
        let cut: String = clean.chars().take(200).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Item {
        a: i32,
    }

    #[test]
    fn parses_plain_array() {
        let items: Vec<Item> = extract_array(r#"[{"a":1},{"a":2}]"#).unwrap();
        assert_eq!(items, vec![Item { a: 1 }, Item { a: 2 }]);
    }

    #[test]
    fn parses_array_wrapped_in_markdown_fence() {
        let raw = "Berikut hasilnya:\n```json\n[{\"a\":7}]\n```\nSemoga membantu.";
        let items: Vec<Item> = extract_array(raw).unwrap();
        assert_eq!(items, vec![Item { a: 7 }]);
    }

    #[test]
    fn ignores_brackets_inside_strings() {
        // Kalau pencarian kedalaman tidak sadar-string, ini akan berhenti
        // di `]` pertama dan gagal parse.
        let raw = r#"[{"a":1},"teks dengan ] kurung"]"#;
        let slice = balanced_array(raw).unwrap();
        assert_eq!(slice, raw);
    }

    #[test]
    fn fails_when_no_array_present() {
        assert!(extract_array::<Item>("maaf, saya tidak bisa membantu").is_err());
    }

    #[test]
    fn empty_array_is_valid() {
        let items: Vec<Item> = extract_array("[]").unwrap();
        assert!(items.is_empty());
    }
}
