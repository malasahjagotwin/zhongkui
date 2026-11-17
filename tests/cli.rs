//! Test end-to-end: menjalankan binary hasil build sebagai proses terpisah.
//!
//! Unit test di dalam `src/` menguji fungsi; berkas ini menguji **kontrak
//! CLI** — exit code, bentuk keluaran, dan janji yang tertulis di README.
//! Perbedaan itu penting: bug seperti "menyaring semua temuan lalu mencetak
//! 'Tidak ada temuan'" hanya muncul di lapisan ini.
//!
//! `CARGO_BIN_EXE_<nama>` disediakan cargo untuk integration test, jadi tidak
//! perlu target `lib` dan tidak perlu menebak lokasi binary.

use std::path::PathBuf;
use std::process::Command;

const FIXTURE: &str = "tests/fixtures/vulnerable";

/// Nilai yang sengaja ditanam di fixture. Tidak boleh pernah muncul utuh di
/// keluaran mana pun.
const RAW_AWS_KEY: &str = "AKIAQWERTYUIOPASDFGH";
const RAW_GITHUB_TOKEN: &str = "ghp_9fXk2mQz7pLw4nRt8vBc3dHs6jYe1aUo5iKp";

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_zhongkui"))
        .args(args)
        .output()
        .expect("gagal menjalankan binary zhongkui");

    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

#[test]
fn version_and_help_work() {
    let v = run(&["--version"]);
    assert_eq!(v.code, 0, "exit code --version harus 0");
    assert!(v.stdout.contains("zhongkui"), "stdout: {}", v.stdout);

    let h = run(&["--help"]);
    assert_eq!(h.code, 0);
    assert!(
        h.stdout.contains("audit"),
        "help harus menyebut subperintah audit"
    );
    assert!(
        h.stdout.contains("deps"),
        "help harus menyebut subperintah deps"
    );
}

#[test]
fn audit_detects_known_vulnerabilities() {
    let o = run(&["audit", FIXTURE, "--format", "grep"]);
    assert_eq!(
        o.code, 0,
        "audit yang berhasil harus exit 0; stderr: {}",
        o.stderr
    );

    for rule in [
        "secret/aws-access-key",
        "secret/github-token",
        "pattern/tls-verify-disabled",
        "pattern/shell-exec",
        "pattern/sql-string-concat",
        "pattern/weak-hash",
        "pattern/unsafe-block",
    ] {
        assert!(
            o.stdout.contains(rule),
            "rule `{rule}` tidak muncul di keluaran:\n{}",
            o.stdout
        );
    }
}

/// Janji keamanan paling penting dari tool ini: laporan tidak boleh memuat
/// nilai rahasia utuh. Kalau test ini gagal, tool-nya sendiri jadi jalur
/// kebocoran dan itu harus dianggap blocker rilis.
#[test]
fn never_prints_raw_secret_value() {
    // Sengaja tanpa --min-severity: semua kanal keluaran ikut diuji.
    let o = run(&["audit", FIXTURE]);

    for (label, text) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
        assert!(
            !text.contains(RAW_AWS_KEY),
            "{label} membocorkan AWS access key utuh:\n{text}"
        );
        assert!(
            !text.contains(RAW_GITHUB_TOKEN),
            "{label} membocorkan GitHub token utuh:\n{text}"
        );
    }

    // Tetapi bukan berarti disensor habis — sebagian harus tetap terlihat
    // supaya pemakai bisa mengenali kredensial mana yang bocor.
    assert!(
        o.stdout.contains("AKIA"),
        "nilai rahasia harus tetap dikenali sebagian, bukan hilang total"
    );
}

#[test]
fn grep_format_is_stable_and_pipeable() {
    let o = run(&["audit", FIXTURE, "--format", "grep"]);
    assert_eq!(o.code, 0);

    let lines: Vec<&str> = o.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "format grep tidak boleh kosong untuk fixture rentan"
    );

    for line in &lines {
        // Bentuk: file:line:SEVERITY:rule_id:pesan
        let parts: Vec<&str> = line.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5, "baris grep tidak sesuai bentuk: {line}");

        let line_no: usize = parts[1]
            .parse()
            .unwrap_or_else(|_| panic!("nomor baris bukan angka pada: {line}"));
        let _ = line_no;

        assert!(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].contains(&parts[2]),
            "severity tidak dikenal pada: {line}"
        );
        assert!(!parts[3].is_empty(), "rule_id kosong pada: {line}");
    }

    // Format grep harus bebas kode warna ANSI supaya aman di-pipe ke grep.
    assert!(
        !o.stdout.contains('\u{1b}'),
        "format grep mengandung escape ANSI sehingga tidak ramah pipe"
    );
}

#[test]
fn min_severity_filters_lower_findings() {
    let o = run(&[
        "audit",
        FIXTURE,
        "--format",
        "grep",
        "--min-severity",
        "critical",
    ]);
    assert_eq!(o.code, 0);

    let lines: Vec<&str> = o.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "fixture punya 2 temuan critical, seharusnya tidak kosong"
    );

    for line in lines {
        assert!(
            line.contains(":CRITICAL:"),
            "--min-severity critical masih meloloskan: {line}"
        );
    }
}

#[test]
fn source_filter_excludes_llm_findings_without_llm_flags() {
    let o = run(&["audit", FIXTURE, "--format", "grep", "--source", "llm"]);
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.trim().is_empty(),
        "tanpa --llm/--llm-discover seharusnya tidak ada temuan bersumber llm:\n{}",
        o.stdout
    );

    let rule = run(&["audit", FIXTURE, "--format", "grep", "--source", "rule"]);
    assert_eq!(rule.code, 0);
    assert!(
        !rule.stdout.trim().is_empty(),
        "--source rule seharusnya tetap menampilkan temuan deterministik"
    );
}

#[test]
fn no_ignore_includes_gitignored_files() {
    // `.env` di fixture ter-gitignore, jadi default tidak dipindai.
    let default = run(&["audit", FIXTURE, "--format", "grep"]);
    assert!(
        !default.stdout.contains("secret/env-file"),
        ".env tidak boleh ikut terpindai saat .gitignore dihormati"
    );

    let all = run(&["audit", FIXTURE, "--format", "grep", "--no-ignore"]);
    assert!(
        all.stdout.contains("secret/env-file"),
        "--no-ignore seharusnya memindai .env dan menandainya:\n{}",
        all.stdout
    );
}

#[test]
fn clean_directory_reports_no_findings() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("zhongkui-test-clean-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("gagal membuat direktori uji");
    std::fs::write(
        dir.join("bersih.rs"),
        "fn main() {\n    println!(\"halo\");\n}\n",
    )
    .expect("gagal menulis berkas uji");

    let o = run(&["audit", dir.to_str().unwrap()]);

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(o.code, 0, "stderr: {}", o.stderr);
    assert!(
        o.stdout.to_lowercase().contains("tidak ada temuan"),
        "direktori bersih seharusnya melaporkan tidak ada temuan:\n{}",
        o.stdout
    );
}

#[test]
fn deps_offline_lists_packages_without_network() {
    let o = run(&["deps", "Cargo.lock", "--offline"]);
    assert_eq!(o.code, 0, "stderr: {}", o.stderr);
    assert!(
        o.stdout.contains("serde"),
        "daftar paket offline seharusnya memuat dependency yang jelas ada:\n{}",
        o.stdout
    );
}

#[test]
fn invalid_lockfile_fails_with_nonzero_exit() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("zhongkui-test-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("gagal membuat direktori uji");
    let path = dir.join("Bukan.lock");
    std::fs::write(&path, "ini bukan toml [[[ valid").expect("gagal menulis berkas uji");

    let o = run(&["deps", path.to_str().unwrap(), "--offline"]);

    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(
        o.code, 0,
        "lockfile rusak harus menghasilkan exit code bukan-nol"
    );
    assert!(
        o.stderr.to_lowercase().contains("error"),
        "kegagalan harus dijelaskan di stderr:\n{}",
        o.stderr
    );
}

/// Path yang salah ketik harus GAGAL, bukan melaporkan "bersih". Sebelumnya
/// `audit ./salah-ketik` keluar dengan exit 0 dan "Tidak ada temuan." —
/// jaminan palsu yang berbahaya kalau dipakai di pipeline.
#[test]
fn missing_path_fails_loudly() {
    let missing =
        std::env::temp_dir().join(format!("zhongkui-pasti-tidak-ada-{}", std::process::id()));

    let o = run(&["audit", missing.to_str().unwrap()]);

    assert_ne!(o.code, 0, "path yang tidak ada harus exit bukan-nol");
    assert!(
        o.stderr.to_lowercase().contains("tidak ditemukan"),
        "stderr harus menyebut path tidak ditemukan:\n{}",
        o.stderr
    );
}

/// Temuan yang tersaring filter tidak boleh dilaporkan sebagai "tidak ada
/// temuan" — itu membuat pembaca menyimpulkan kode bersih.
#[test]
fn filtered_findings_are_reported_as_filtered() {
    let o = run(&["audit", FIXTURE, "--source", "llm"]);
    assert_eq!(o.code, 0);

    let text = o.stdout.to_lowercase();
    assert!(
        text.contains("tersaring"),
        "harus menjelaskan bahwa hasil tersaring, bukan mengaku kosong:\n{}",
        o.stdout
    );
}

#[test]
fn json_reports_hidden_count() {
    let o = run(&["audit", FIXTURE, "--source", "llm", "--format", "json"]);
    assert_eq!(o.code, 0, "stderr: {}", o.stderr);

    let v: serde_json::Value =
        serde_json::from_str(&o.stdout).expect("keluaran --format json harus JSON valid");

    let hidden = v["summary"]["hidden_by_filter"]
        .as_u64()
        .expect("summary.hidden_by_filter harus ada");
    assert!(
        hidden > 0,
        "dengan --source llm semua temuan rule tersaring, hidden_by_filter harus > 0"
    );
}

#[test]
fn deps_offline_honors_json_format() {
    let o = run(&["deps", "Cargo.lock", "--offline", "--format", "json"]);
    assert_eq!(o.code, 0, "stderr: {}", o.stderr);

    let v: serde_json::Value =
        serde_json::from_str(&o.stdout).expect("--offline --format json harus menghasilkan JSON");

    let packages = v["packages"]
        .as_array()
        .expect("mode offline JSON harus punya array packages");
    assert!(!packages.is_empty(), "daftar paket tidak boleh kosong");
}

/// Snippet berasal dari berkas yang tidak dipercaya. Escape sequence ANSI di
/// dalamnya bisa membersihkan layar lalu mencetak teks palsu di atas temuan
/// asli, sehingga auditor menyimpulkan kode bersih.
#[test]
fn terminal_escape_sequences_are_neutralized() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("zhongkui-test-esc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("gagal membuat direktori uji");

    // Baris ini cocok dengan pattern/eval sekaligus membawa urutan escape.
    let payload = "x = eval(\"\u{1b}[2J\u{1b}[HAman: 0 temuan\")\n";
    std::fs::write(dir.join("jahat.py"), payload).expect("gagal menulis berkas uji");

    let o = run(&["audit", dir.to_str().unwrap()]);

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(o.code, 0, "stderr: {}", o.stderr);
    assert!(
        !o.stdout.contains("\u{1b}[2J"),
        "snippet mencetak escape clear-screen ke terminal:\n{:?}",
        o.stdout
    );
    assert!(
        o.stdout.contains("pattern/eval") || o.stdout.contains("eval"),
        "temuan eval tetap harus dilaporkan:\n{}",
        o.stdout
    );
}
