//! Klien untuk endpoint OpenAI-compatible.
//!
//! Endpoint ini dipakai karena menyediakan `ds-meji` lewat API yang sama
//! bentuknya dengan OpenAI, jadi kalau nanti mau pindah provider cukup ganti
//! env `LELUHUR_BASE_URL`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_BASE_URL: &str = "https://leluhurcy.us.ci/v1";
pub const DEFAULT_MODEL: &str = "ds-meji";
pub const API_KEY_ENV: &str = "LELUHUR_API_KEY";

const MAX_ATTEMPTS: u32 = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct LlmClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    stream: bool,
    temperature: f32,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    /// Model reasoning kadang menaruh jawabannya di `reasoning_content`
    /// dan meninggalkan `content` kosong.
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
}

impl LlmClient {
    /// Bangun klien dari environment.
    ///
    /// API key **tidak pernah** dibaca dari file di dalam repo — hanya dari
    /// env var, supaya kredensial nggak gampang ikut ter-commit.
    pub fn from_env(model_override: Option<String>) -> Result<Self> {
        let api_key = std::env::var(API_KEY_ENV).with_context(|| {
            format!("env `{API_KEY_ENV}` belum diset. Contoh: export {API_KEY_ENV}=sk-...")
        })?;

        if api_key.trim().is_empty() {
            bail!("env `{API_KEY_ENV}` kosong");
        }

        let base_url = std::env::var("LELUHUR_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let model = model_override
            .or_else(|| std::env::var("ZHONGKUI_MODEL").ok())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());

        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("gagal membangun HTTP client")?;

        Ok(Self {
            http,
            base_url,
            api_key,
            model,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Kirim satu percakapan, kembalikan teks jawaban.
    ///
    /// Retry hanya untuk error yang memang layak diulang (429 dan 5xx).
    /// 4xx lain berarti permintaan kita yang salah, mengulangnya cuma
    /// membuang kuota.
    pub async fn chat(&self, system: &str, user: &str) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = ChatRequest {
            model: &self.model,
            messages: vec![
                Message {
                    role: "system",
                    content: system,
                },
                Message {
                    role: "user",
                    content: user,
                },
            ],
            stream: false,
            temperature: 0.0,
        };

        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 1..=MAX_ATTEMPTS {
            let sent = self
                .http
                .post(&url)
                .bearer_auth(&self.api_key)
                .json(&body)
                .send()
                .await;

            let response = match sent {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(anyhow::Error::new(e).context("request ke LLM gagal"));
                    backoff(attempt).await;
                    continue;
                }
            };

            let status = response.status();
            // Kegagalan membaca body juga layak di-retry. Sebelumnya `?` di
            // sini membatalkan seluruh audit untuk gangguan transien yang
            // sama-sama sementara dengan kegagalan `send()`.
            let text = match response.text().await {
                Ok(text) => text,
                Err(e) => {
                    last_err =
                        Some(anyhow::Error::new(e).context("gagal membaca body respons LLM"));
                    backoff(attempt).await;
                    continue;
                }
            };

            if status.is_success() {
                return parse_content(&text);
            }

            let retryable = status.as_u16() == 429 || status.is_server_error();
            last_err = Some(anyhow::anyhow!(
                "LLM mengembalikan HTTP {}: {}",
                status,
                truncate(&text, 400)
            ));

            if !retryable {
                break;
            }
            backoff(attempt).await;
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("permintaan LLM gagal tanpa keterangan")))
    }
}

fn parse_content(body: &str) -> Result<String> {
    let parsed: ChatResponse = serde_json::from_str(body).with_context(|| {
        format!(
            "respons bukan JSON yang diharapkan: {}",
            truncate(body, 300)
        )
    })?;

    let message = parsed
        .choices
        .into_iter()
        .next()
        .context("respons LLM tidak punya pilihan (choices kosong)")?
        .message;

    match (message.content, message.reasoning_content) {
        (Some(c), _) if !c.trim().is_empty() => Ok(c),
        // Sebagian model reasoning mengosongkan `content` dan menaruh
        // seluruh keluarannya di `reasoning_content`.
        (_, Some(r)) if !r.trim().is_empty() => Ok(r),
        _ => bail!("LLM mengembalikan jawaban kosong"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

async fn backoff(attempt: u32) {
    // 1s, 2s — cukup untuk rate limit transien tanpa bikin CLI terasa hang.
    let secs = 1u64 << (attempt.saturating_sub(1).min(3));
    tokio::time::sleep(Duration::from_secs(secs)).await;
}
