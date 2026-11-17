//! zhongkui — auditor keamanan source code dengan bantuan LLM.

mod audit;
mod cli;
mod deps;
mod finding;
mod json;
mod llm;
mod report;
mod rules;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use colored::Colorize;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: gagal membuat runtime async: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(exit) => exit,
        Err(e) => {
            // `{:#}` mencetak rantai penyebab: "konteks: penyebab: akar masalah".
            // Tanpa ini, pesan errornya cuma lapisan terluar dan sulit didiagnosis.
            eprintln!("{} {e:#}", "error:".red().bold());
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Audit(args) => {
            audit::run(args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Deps(args) => {
            deps::run(args).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}
