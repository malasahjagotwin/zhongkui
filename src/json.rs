//! Ekstraksi JSON dari keluaran model bahasa.
//!
//! Model sering membungkus JSON dengan pagar markdown, kalimat pembuka, atau
//! referensi bertanda kurung seperti `[CWE-79]`. Parser yang kaku akan gagal
//! padahal isi jawabannya benar — jadi di sini kita mencoba **setiap** array
//! yang seimbang, berurutan, sampai ada yang cocok dengan skema yang diminta.
//!
//! Versi sebelumnya hanya mengambil array seimbang pertama. Kalau model menulis
//! "terkait [CWE-79]: ..." sebelum array-nya, yang terambil adalah `[CWE-79]`,
//! deserialisasi gagal, dan seluruh batch dibuang diam-diam.

use anyhow::{Result, bail};

/// Ambil dan parse array JSON pertama yang **cocok dengan skema** `T`.
pub fn extract_array<T: serde::de::DeserializeOwned>(raw: &str) -> Result<Vec<T>> {
    let cleaned = strip_fences(raw);

    let mut last_schema_error: Option<String> = None;
    let mut from = 0usize;

    while let Some(offset) = cleaned[from..].find('[') {
        let start = from + offset;

        let Some(slice) = balanced_array_from(&cleaned, start) else {
            // Kurung tidak pernah seimbang lagi setelah titik ini.
            break;
        };

        match serde_json::from_str::<Vec<T>>(slice) {
            Ok(values) => return Ok(values),
            Err(e) => {
                last_schema_error = Some(format!("{} (pada {})", e, preview(slice)));
                // Lanjut ke '[' berikutnya. `[` adalah ASCII, jadi start + 1
                // selalu berada di batas karakter.
                from = start + 1;
            }
        }
    }

    match last_schema_error {
        Some(e) => bail!("tidak ada array JSON yang cocok dengan skema yang diharapkan: {e}"),
        None => bail!(
            "tidak menemukan array JSON pada keluaran model: {}",
            preview(raw)
        ),
    }
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

/// Dari posisi `start` yang menunjuk `[`, lacak kedalaman kurung untuk
/// menemukan penutupnya — dengan mengabaikan `[`/`]` di dalam string.
fn balanced_array_from(s: &str, start: usize) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.get(start) != Some(&b'[') {
        return None;
    }

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
        format!("{cut}...")
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
        let slice = balanced_array_from(raw, 0).unwrap();
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

    /// Regresi: rujukan bertanda kurung di prosa model tidak boleh membuat
    /// seluruh jawaban dibuang.
    #[test]
    fn skips_prose_brackets_before_real_array() {
        let raw = "Masalah ini terkait [CWE-79](https://cwe.mitre.org/data/definitions/79.html):\n[{\"a\":5}]";
        let items: Vec<Item> = extract_array(raw).unwrap();
        assert_eq!(items, vec![Item { a: 5 }]);
    }

    #[test]
    fn skips_numeric_bracket_reference() {
        let raw = "Berikut hasilnya [1]:\n[{\"a\":9}]";
        let items: Vec<Item> = extract_array(raw).unwrap();
        assert_eq!(items, vec![Item { a: 9 }]);
    }

    /// Array yang bentuknya bukan yang diminta dilewati, bukan dianggap sukses
    /// atau menggagalkan seluruh pencarian.
    #[test]
    fn skips_array_of_wrong_shape() {
        let raw = r#"[1,2,3] lalu [{"a":4}]"#;
        let items: Vec<Item> = extract_array(raw).unwrap();
        assert_eq!(items, vec![Item { a: 4 }]);
    }
}
