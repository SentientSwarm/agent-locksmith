use super::*;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use std::{collections::BTreeMap, sync::Mutex, time::Duration};

impl Runtime {
    pub(super) async fn callback(
        &self,
        state: &str,
        issuer: &str,
        code: Option<&str>,
    ) -> Result<()> {
        let _permit = self
            .operations
            .try_acquire()
            .map_err(|_| Error("capacity"))?;
        let outer_deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        let attempt = tokio::time::timeout_at(outer_deadline, self.claim(state, issuer))
            .await
            .map_err(|_| Error("operation_incomplete"))??;
        let id: &str = attempt.get("id");
        let stage = Arc::new(Mutex::new("claimed"));
        let checked = Arc::new(Mutex::new(None));
        if code.is_none() {
            self.fail(id, "callback", "authorization_denied").await?;
            return Err(Error("authorization_denied"));
        }
        let deadline = outer_deadline.min(
            tokio::time::Instant::now()
                + Duration::from_secs((attempt.get::<i64, _>("deadline") - now()).max(0) as u64),
        );
        // The stage lives outside the timed future; timeout does not erase it.
        let result = tokio::time::timeout_at(
            deadline,
            self.operate(&attempt, code.unwrap(), stage.clone(), checked.clone()),
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => checked
                .lock()
                .expect("checked outcome")
                .unwrap_or(Err(Error("operation_incomplete"))),
        };
        if let Err(error) = result {
            let phase = *stage.lock().expect("stage");
            // A submitted COMMIT may have succeeded. Never change a connected
            // attempt, and retain the primary reason even if this write fails.
            let _ =
                tokio::time::timeout(Duration::from_secs(5), self.fail(id, phase, error.0)).await;
        }
        result
    }

    async fn operate(
        &self,
        a: &SqliteRow,
        code: &str,
        stage: Arc<Mutex<&'static str>>,
        outcome: Arc<Mutex<Option<Result<()>>>>,
    ) -> Result<()> {
        let p = self.profile(a.get("profile_id"))?;
        let verifier: SecretString = String::from_utf8(
            self.key
                .unseal(a.get("verifier_ct"), a.get("verifier_nonce"))?,
        )
        .map_err(|_| Error("sealing_failed"))?
        .into();
        *stage.lock().expect("stage") = "token";
        self.check(a).await?;
        let token = token::exchange(p, code, verifier.expose_secret()).await?;
        self.check(a).await?;
        self.quarantine(a, &token).await?;
        let mut wire = wire::Wire::new(self, a, token.access.expose_secret(), stage.clone())?;
        let checked = match identity(&mut wire, p, &token).await {
            Err(error) => Err(error),
            Ok(()) => {
                *stage.lock().expect("stage") = "publication";
                self.publish(a, &token).await.map(|_| ())
            }
        };
        // Retain the checked outcome outside cleanup and the outer timeout.
        // Only committed custody is a success, never token/identity alone.
        *outcome.lock().expect("checked outcome") = Some(checked);
        if let Err(error) = checked {
            let phase = *stage.lock().expect("stage");
            let _ = self.fail(a.get("id"), phase, error.0).await;
        }
        let cleanup = tokio::time::timeout(Duration::from_secs(6), wire.close())
            .await
            .unwrap_or("incomplete");
        let _ = self
            .diagnostics(
                a.get("id"),
                cleanup,
                if checked.is_ok() {
                    "committed"
                } else {
                    "failure_recorded"
                },
            )
            .await;
        checked
    }

    pub(super) async fn shutdown(&self) -> Result<()> {
        sqlx::query("UPDATE oauth_consent_attempts SET state='failed',reason='daemon_stopped',updated_at=?,version=version+1,state_hash=NULL,verifier_ct=NULL,verifier_nonce=NULL,quarantine_ct=NULL,quarantine_nonce=NULL WHERE run_id=? AND state IN ('pending','exchanging')")
            .bind(now()).bind(&self.run_id).execute(&self.pool).await?;
        Ok(())
    }
}
async fn identity(w: &mut wire::Wire<'_>, p: &config::Profile, token: &token::Token) -> Result<()> {
    w.initialize().await?;
    w.enter("list");
    let result = w.rpc("tools/list", json!({})).await?;
    token.screen(&result)?;
    w.enter("schema");
    if result.get("nextCursor").is_some_and(|v| !v.is_null()) {
        return Err(Error("pagination_unsupported"));
    }
    let tools = result["tools"]
        .as_array()
        .filter(|t| t.len() <= 256)
        .ok_or(Error("tool_limit"))?;
    let mut found = BTreeMap::new();
    for tool in tools {
        let name = tool["name"].as_str().ok_or(Error("tool_invalid"))?;
        if found.insert(name, tool).is_some() {
            return Err(Error("duplicate_tool"));
        }
    }
    for (name, arguments) in [
        ("get_workspace", json!({})),
        ("get_user", json!({"query":"me"})),
    ] {
        let tool = found.get(name).ok_or(Error("required_tool_unavailable"))?;
        if tool["annotations"]["destructiveHint"] == true {
            return Err(Error("schema_unsupported"));
        }
        // Check the actual fixed arguments with the existing finite grammar.
        // We supply only declared fields, so omitted/true root additionalProperties
        // can be closed for this local check without changing the provider schema.
        let mut schema = tool["inputSchema"].clone();
        let object = schema.as_object_mut().ok_or(Error("schema_unsupported"))?;
        if !object.contains_key("additionalProperties")
            || object.get("additionalProperties") == Some(&Value::Bool(true))
        {
            object.insert("additionalProperties".into(), Value::Bool(false));
        }
        crate::native_authority::values::validate(&schema, &arguments)
            .map_err(|_| Error("schema_unsupported"))?;
    }
    for (stage, name, args, expected) in [
        (
            "workspace",
            "get_workspace",
            json!({}),
            &p.expected_workspace,
        ),
        ("user", "get_user", json!({"query":"me"}), &p.expected_user),
    ] {
        w.enter(stage);
        let result = w
            .rpc("tools/call", json!({"name":name,"arguments":args}))
            .await?;
        token.screen(&result)?;
        let value = object(&result)?;
        token.screen(&value)?;
        if value["id"] != expected.as_str() {
            return Err(Error(if stage == "workspace" {
                "workspace_mismatch"
            } else {
                "user_mismatch"
            }));
        }
    }
    Ok(())
}
fn object(result: &Value) -> Result<Value> {
    if result["isError"] == true {
        return Err(Error("tool_error"));
    }
    if result.get("structuredContent").is_some() {
        return Err(Error("structured_content_unsupported"));
    }
    let content = result["content"]
        .as_array()
        .ok_or(Error("content_unsupported"))?;
    let [item] = content.as_slice() else {
        return Err(Error("content_unsupported"));
    };
    if item["type"] != "text" {
        return Err(Error("content_unsupported"));
    }
    let value = parse(
        item["text"]
            .as_str()
            .ok_or(Error("content_unsupported"))?
            .as_bytes(),
    )?;
    if !value.is_object() {
        return Err(Error("content_unsupported"));
    }
    Ok(value)
}
