//! Telegram Bot API.

use super::{with_retries, Alert, AlertKind};
use anyhow::{bail, Result};
use serde_json::json;

pub struct Telegram {
    client: reqwest::Client,
    bot_token: String,
    chat_ids: Vec<String>,
}

/// Telegram's HTML parse mode rejects a message containing a stray `<` or `&`,
/// and validator detail strings are full of both.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl Telegram {
    pub fn new(client: reqwest::Client, bot_token: String, chat_ids: Vec<String>) -> Self {
        Self {
            client,
            bot_token,
            chat_ids,
        }
    }

    pub fn chat_count(&self) -> usize {
        self.chat_ids.len()
    }

    pub async fn send(&self, alert: &Alert, source: &str) -> Result<()> {
        let icon = match alert.kind {
            AlertKind::Trigger => "🚨",
            AlertKind::Resolve => "✅",
            AlertKind::Info => "ℹ️",
        };

        let mut text = format!(
            "{icon} <b>{}</b>\n{}",
            escape(&alert.title),
            escape(&alert.body)
        );
        text.push_str(&format!("\n<i>{}</i>", escape(source)));

        // Telegram hard-caps messages at 4096 characters and rejects the whole
        // message if exceeded, so a long list of failing endpoints must not cost
        // us the alert.
        if text.chars().count() > 4000 {
            let truncated: String = text.chars().take(3980).collect();
            text = format!("{truncated}\n…(truncated)");
        }

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        // Delivered one chat at a time, and one failure does not stop the rest:
        // a single blocked or deleted chat must not silence everybody else.
        let mut failures = Vec::new();
        for chat_id in &self.chat_ids {
            let body = json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            });

            let result = with_retries(4, || {
                let client = self.client.clone();
                let url = url.clone();
                let body = body.clone();
                async move {
                    // The URL holds the bot token.
                    let resp = client
                        .post(&url)
                        .json(&body)
                        .send()
                        .await
                        .map_err(crate::rpc::scrub)?;
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    let text = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::UNAUTHORIZED
                        || status == reqwest::StatusCode::FORBIDDEN
                    {
                        bail!("rejected the bot token or chat id ({status}): {text}");
                    }
                    // 400 for a chat id is permanent -- wrong id, or the bot was
                    // never messaged. Retrying will not fix it.
                    if status == reqwest::StatusCode::BAD_REQUEST {
                        bail!("bad request ({status}): {text}");
                    }
                    bail!("returned {status}: {text}")
                }
            })
            .await;

            if let Err(e) = result {
                failures.push(format!("chat {chat_id}: {e}"));
            }
        }

        match failures.len() {
            0 => Ok(()),
            n if n == self.chat_ids.len() => {
                bail!("telegram delivery failed to all {n} chat(s): {}", failures.join("; "))
            }
            n => bail!(
                "telegram delivered to {} of {} chat(s); failed: {}",
                self.chat_ids.len() - n,
                self.chat_ids.len(),
                failures.join("; ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(escape("a & b < c > d"), "a &amp; b &lt; c &gt; d");
    }

    #[test]
    fn escaping_leaves_ordinary_validator_detail_alone() {
        let s = "chimps-1 delinquent, last vote slot 312874911";
        assert_eq!(escape(s), s);
    }
}
