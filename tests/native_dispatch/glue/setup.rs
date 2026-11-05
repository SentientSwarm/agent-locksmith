use crate::{Error, pki, process, support::Setup};
use agent_locksmith::{native_authority::runtime::Runtime, registrations::AuthSpec};
use serde_json::json;
use std::{path::Path, time::Duration};

pub async fn receiver(path: &Path, script: &str) -> Result<(process::Guard, u16), Error> {
    let log = std::fs::File::create(path.join("receiver.log"))?;
    let mut c = process::command("python3");
    c.env("PYTHONDONTWRITEBYTECODE", "1");
    c.arg(script).arg(path).stdout(log.try_clone()?).stderr(log);
    let mut child = process::Guard(c.spawn()?);
    let port = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.0.try_wait().unwrap().is_none());
            if let Ok(bytes) = std::fs::read(path.join("receiver-port.json"))
                && let Ok(port) = serde_json::from_slice::<u16>(&bytes)
            {
                return port;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok((child, port))
}
pub async fn prepare(script: &str) -> Result<(Setup, process::Guard), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut s = Setup::new().await;
    let cert = pki::Pki::write(s.f._dir.path());
    let (receiver, port) = receiver(s.f._dir.path(), script).await?;
    destination(&s, port).await?;
    s.rt = Runtime::new(
        s.f.repo.clone(),
        s.f.catalog.clone(),
        None,
        vec![locksmith_mcp_transport::Certificate::from_pem(
            cert.ca.as_bytes(),
        )?],
        Default::default(),
    )
    .await?;
    if std::env::var_os("LOCKSMITH_TEST_CONTROLLED_OAUTH").is_some() {
        let p = crate::controlled::profile(s.f._dir.path(), port);
        crate::controlled::configure(&s, &p).await;
        crate::controlled::insert(&s, &p, &crate::controlled::key(), "x", "owner").await;
        s.rt = crate::controlled::runtime(&s, p, crate::controlled::key()).await;
        crate::controlled::select(&s).await;
    }
    approve(&s).await?;
    Ok((s, receiver))
}
async fn approve(s: &Setup) -> Result<(), Error> {
    let tool = json!({"name":"read","inputSchema":{"type":"object","properties":{"ticket":{"type":"string"}},"additionalProperties":false}});
    std::fs::write(
        s.f._dir.path().join("manifest.json"),
        json!({"tools":[tool]}).to_string(),
    )?;
    let source = s.current().await.source;
    let owner = std::env::var_os("LOCKSMITH_TEST_CONTROLLED_OAUTH").map(|_| "owner");
    let state =
        s.rt.observe_for(owner, &s.agent, "native", &source, None)
            .await?;
    let entry = &state["observation"]["manifest"]["tools"][0];
    let input = serde_json::from_value(
        json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"read","observed_digest":entry["observed_digest"],"effect":"read"}),
    )?;
    let reviewed = s.rt.review_for(owner, &s.agent, "native", input).await?;
    s.rt.replace_for(
        owner,
        &s.agent,
        "native",
        Setup::replace(
            &state,
            json!([{"name":"read","contract_digest":reviewed["contract_digest"]}]),
        ),
    )
    .await?;
    Ok(())
}

async fn destination(s: &Setup, port: u16) -> Result<(), Error> {
    let mut r = s.f.repo.get("native").await?.unwrap();
    r.upstream = format!("https://localhost:{port}/mcp");
    r.mcp.as_mut().unwrap().allow_private_destination = true;
    r.mcp.as_mut().unwrap().compact = crate::COMPACT;
    s.f.repo.upsert(&r).await?;
    s.f.agents
        .update_policy(
            &s.agent,
            Some(Some(vec!["native".into()])),
            None,
            None,
            None,
        )
        .await?;
    s.f.bindings
        .set(s.f.agent_id, "native", &AuthSpec::None)
        .await?;
    s.f.refresh().await;
    Ok(())
}
