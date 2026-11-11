//! `locksmith oauth device-login` (#138): sign a ChatGPT-plan (Codex)
//! session in again from the operator CLI. The daemon talks to the
//! provider and keeps the tokens; this command only shows the one-time
//! code and waits for the sign-in.

use serde_json::{Value, json};
use std::time::Duration;

use super::with_label_query;
use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

pub async fn run(
    client: &CliClient,
    format: Format,
    name: &str,
    label: Option<&str>,
    replace: bool,
) -> Result<(), CliError> {
    let op = CliClient::op_token()?;
    let base = format!("/admin/operator/oauth/{name}/device-login");
    let started: Value = client
        .json(
            "POST",
            &with_label_query(&base, label)?,
            Auth::Operator(&op),
            Some(&json!({"replace": replace})),
        )
        .await?;
    let (Some(attempt), Some(url), Some(code)) = (
        started["attempt"].as_str(),
        started["verification_url"].as_str(),
        started["user_code"].as_str(),
    ) else {
        return Err(CliError::Server {
            status: 502,
            body: "daemon returned an incomplete device login".into(),
        });
    };
    // The code is for a person; keep stdout for the final result.
    eprintln!(
        "Open {url} and enter code {code} (expires in {} minutes).\n\
         Sign in with the account for session {:?}. Waiting...",
        started["expires_in"].as_u64().unwrap_or(900) / 60,
        started["session_label"].as_str().unwrap_or("default"),
    );
    let mut interval = started["interval"].as_u64().unwrap_or(5);
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let polled: Value = client
            .json(
                "GET",
                &format!("{base}/{attempt}"),
                Auth::Operator(&op),
                None,
            )
            .await?;
        if polled["status"] == "complete" {
            print(&polled["session"], format);
            return Ok(());
        }
        interval = polled["interval"].as_u64().unwrap_or(interval);
    }
}
