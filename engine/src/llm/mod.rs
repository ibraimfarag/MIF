//! L5 "Mind": local LLM assistant (LM Studio, OpenAI-compatible) +
//! natural-language command bar with an offline regex fallback.
//!
//! Security rule: the LLM can ONLY emit whitelisted commands; anything else
//! is dropped. Offline, ~20 common intents are matched with regex.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct NlResult {
    pub matched: bool,
    pub command: String,
    pub params: serde_json::Value,
    pub via: String, // "regex" | "llm" | "none"
    pub reply: String,
}

/// Offline intent matching — Egyptian Arabic + English, ~20 intents.
pub fn parse_nl(input: &str) -> NlResult {
    let lowered = input.trim().to_lowercase();

    let intents: Vec<(&str, Regex, &str, serde_json::Value)> = vec![
        (
            "scan_downloads",
            Regex::new(r"(?i)(افحص|امسح|scan)\s*(مجلد\s*)?(التنزيلات|downloads)").unwrap(),
            "scan.start",
            serde_json::json!({"path": downloads_dir(), "quarantine": false}),
        ),
        (
            "full_audit",
            Regex::new(r"(?i)(افحص|فحص|audit).*(النظام|الجهاز|system)|^audit$").unwrap(),
            "audit.run",
            serde_json::json!({}),
        ),
        (
            "scan_path",
            Regex::new(r#"(?i)(?:افحص|امسح|scan)\s+(?:مجلد\s+)?["']?([A-Za-z]:[\\\/][^"']+)["']?"#).unwrap(),
            "scan.start",
            serde_json::json!({}),
        ),
        (
            "quick_defender_scan",
            Regex::new(r"(?i)(ديفندر|defender).*(فحص|scan)|فحص سريع").unwrap(),
            "defender.scan.quick",
            serde_json::json!({}),
        ),
        (
            "connections",
            Regex::new(r"(?i)(الاتصالات|connections|شبكة|network).*(شوف|عرض|list|show)|شوف الاتصالات").unwrap(),
            "net.connections",
            serde_json::json!({}),
        ),
        (
            "vuln_scan",
            Regex::new(r"(?i)(ثغرات|vulnerab|cve)").unwrap(),
            "vuln.scan",
            serde_json::json!({"max_apps": 10}),
        ),
        (
            "default_deny_on",
            Regex::new(r"(?i)(منع|امنع|block|deny)\s*(كل|all)?\s*(الخروج|outbound)|default.?deny.*(on|enable|فعّل)").unwrap(),
            "fw.default_deny.enable",
            serde_json::json!({}),
        ),
        (
            "default_deny_off",
            Regex::new(r"(?i)(سمح|allow|اعادة)\s*(الخروج|outbound)|default.?deny.*(off|disable|عطّل)").unwrap(),
            "fw.default_deny.disable",
            serde_json::json!({}),
        ),
        (
            "block_country",
            Regex::new(r#"(?i)(احظر|حظر|block)\s*(كل\s*)?(ترافيك|traffic|دولة|country)?\s*(من\s*)?["']?([A-Za-z]{2})["']?$"#).unwrap(),
            "fw.country.block",
            serde_json::json!({}),
        ),
        (
            "fw_rules",
            Regex::new(r"(?i)(قواعد|rules).*(الجدار|firewall)|firewall.*rules").unwrap(),
            "fw.rules.list",
            serde_json::json!({}),
        ),
        (
            "guard_start",
            Regex::new(r"(?i)(شغّل|شغل|start|فعّل|فعل)\s*(الحارس|الحماية|المراقبة|guard|monitor)").unwrap(),
            "guard.start",
            serde_json::json!({}),
        ),
        (
            "guard_stop",
            Regex::new(r"(?i)(اقفل|وقف|stop|عطّل)\s*(الحارس|الحماية|المراقبة|guard|monitor)").unwrap(),
            "guard.stop",
            serde_json::json!({}),
        ),
        (
            "canary_list",
            Regex::new(r"(?i)(فخاخ|فخ|canar)").unwrap(),
            "canary.list",
            serde_json::json!({}),
        ),
        (
            "incidents",
            Regex::new(r"(?i)(حوادث|حادثة|incident)").unwrap(),
            "incident.list",
            serde_json::json!({"limit": 20}),
        ),
        (
            "sync",
            Regex::new(r"(?i)(حدث|زامن|sync|update).*(المعرفة|الذكاء|intel|feeds)").unwrap(),
            "sync.now",
            serde_json::json!({}),
        ),
        (
            "report",
            Regex::new(r"(?i)(تقرير|report|export)").unwrap(),
            "report.export",
            serde_json::json!({"format": "markdown"}),
        ),
    ];

    // Order matters: specific phrases first.
    for (name, re, command, params) in &intents {
        if let Some(caps) = re.captures(&lowered) {
            let mut params = params.clone();
            // Fill dynamic captures.
            if *name == "scan_path"
                && let Some(p) = caps.get(1) {
                    params["path"] = serde_json::Value::String(p.as_str().to_string());
                }
            if *name == "block_country"
                && let Some(cc) = caps.get(5) {
                    params["country"] =
                        serde_json::Value::String(cc.as_str().to_uppercase());
                }
            return NlResult {
                matched: true,
                command: (*command).to_string(),
                params,
                via: "regex".into(),
                reply: format!("Matched intent '{name}' — running {command}"),
            };
        }
    }

    NlResult {
        matched: false,
        command: String::new(),
        params: serde_json::json!({}),
        via: "none".into(),
        reply: "لم أفهم الأمر — جرب: «افحص مجلد التنزيلات» أو «شغل الحارس» أو «تقرير»".into(),
    }
}

fn downloads_dir() -> String {
    std::env::var("USERPROFILE")
        .map(|u| format!("{u}\\Downloads"))
        .unwrap_or_else(|_| r"C:\Users\Public\Downloads".into())
}

// ---------- LM Studio (OpenAI-compatible) ----------

#[derive(Debug, Deserialize)]
struct LmChoice {
    message: LmMessage,
}

#[derive(Debug, Deserialize)]
struct LmMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LmResponse {
    choices: Vec<LmChoice>,
}

pub struct LmClient {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

impl LmClient {
    pub fn new() -> Self {
        let settings = crate::settings::current();
        Self {
            base_url: settings.lm_base(),
            model: settings.lm_name(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn available(&self) -> bool {
        self.client
            .get(format!("{}/v1/models", self.base_url))
            .send()
            .await
            .is_ok()
    }

    /// Explains a security finding in the user's language. Falls back to a
    /// pre-written template when LM Studio is off (graceful degradation).
    pub async fn explain(&self, finding: &str, lang: &str) -> Result<String> {
        if !self.available().await {
            return Ok(template_explain(finding, lang));
        }
        let sys = if lang == "ar" {
            "أنت محلل أمني لمركز MI CS. اشرح النتيجة الأمنية بالمصري المختصر: الخطر إيه، وليه مهم، وإيه الحل. بدون أي أوامر تنفيذية."
        } else {
            "You are the MI CS security analyst. Explain the finding briefly: the risk, why it matters, and the fix. Never emit executable commands."
        };
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": finding}
            ],
            "temperature": 0.3,
            "max_tokens": 400
        });
        let resp = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&body)
            .send()
            .await
            .context("LM Studio request")?;
        if !resp.status().is_success() {
            anyhow::bail!("LM Studio returned {}", resp.status());
        }
        let parsed: LmResponse = resp.json().await.context("LM Studio json")?;
        Ok(parsed
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_else(|| template_explain(finding, lang)))
    }
}

fn template_explain(finding: &str, lang: &str) -> String {
    if lang == "ar" {
        format!(
            "شرح سريع (بدون LLM محلي):\n{finding}\n\nالخطورة دي بتخص إعدادات حماية على جهازك. الأفضل تصلحها من شاشة «مركز التقوية» — كل إصلاح بياخد لقطة قبل التغيير وينفع يترجع."
        )
    } else {
        format!(
            "Quick explanation (local LLM offline):\n{finding}\n\nThis concerns a security setting on your machine. Fix it from the Hardening Center — every fix is snapshotted and can be rolled back."
        )
    }
}
