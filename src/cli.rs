use crate::finding::Severity;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "keris",
    version,
    about = "Auditor keamanan source code dengan bantuan LLM",
    long_about = "keris memindai source code untuk kerentanan dan kredensial hardcoded.\n\
                  Pemindaian rule deterministik berjalan offline; analisis LLM bersifat opt-in\n\
                  karena mengirim isi kode ke endpoint pihak ketiga."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Audit source code untuk kerentanan dan rahasia hardcoded
    Audit(AuditArgs),
    /// Periksa dependency di lockfile terhadap database kerentanan OSV
    Deps(DepsArgs),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    /// Satu temuan per baris (`file:line:SEVERITY:rule:pesan`) untuk grep/CI
    Grep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SourceFilter {
    /// Semua temuan
    All,
    /// Hanya temuan rule deterministik
    Rule,
    /// Hanya temuan dari LLM
    Llm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// File atau direktori yang diaudit
    pub path: PathBuf,

    /// Triage temuan deterministik pakai LLM (butuh LELUHUR_API_KEY)
    #[arg(long)]
    pub llm: bool,

    /// Kirim isi file ke LLM untuk mencari kerentanan yang lolos dari regex
    #[arg(long)]
    pub llm_discover: bool,

    /// Abaikan .gitignore saat menelusuri berkas
    #[arg(long)]
    pub no_ignore: bool,

    /// Format keluaran
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Sembunyikan temuan di bawah tingkat ini
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub min_severity: SeverityArg,

    /// Batasi ke sumber temuan tertentu.
    ///
    /// Berguna karena temuan rule dan LLM bisa menunjuk baris yang sama untuk
    /// masalah yang sama — `--source rule` memberi daftar yang bersih tanpa
    /// duplikasi.
    #[arg(long, value_enum, default_value_t = SourceFilter::All)]
    pub source: SourceFilter,

    /// Timpa nama model (default: env KERIS_MODEL atau `ds-meji`)
    #[arg(long)]
    pub model: Option<String>,
}

#[derive(Args, Debug)]
pub struct DepsArgs {
    /// Lockfile yang diperiksa (saat ini: Cargo.lock)
    pub lockfile: PathBuf,

    /// Jangan panggil API OSV; hanya daftar paket
    #[arg(long)]
    pub offline: bool,

    /// Format keluaran
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Sembunyikan temuan di bawah tingkat ini
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub min_severity: SeverityArg,
}
