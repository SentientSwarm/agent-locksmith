//! Compatibility observations only; all authority and dispatch remain production.
use crate::Error;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

pub struct Prepared(pub PathBuf);
impl Prepared {
    pub fn enable(&self) {
        std::fs::write(
            self.0.join("behavior.json"),
            json!({"prepare_hold":"original-s3"}).to_string(),
        )
        .unwrap();
    }
    pub async fn reached(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !self.0.join("arrived-original-s3.json").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    pub fn resume(&self) {
        std::fs::write(self.0.join("release-original-s3.json"), b"true").unwrap();
    }
}
pub struct Session {
    pub closed: CancellationToken,
}
pub struct Sessions {
    pub id: Arc<Mutex<Option<String>>>,
    pub owner: String,
    pub closed: CancellationToken,
}
impl Sessions {
    pub async fn find(&self, id: &str, owner: &str) -> Result<Session, Error> {
        if owner != self.owner || self.id.lock().unwrap().as_deref() != Some(id) {
            return Err("observer identity mismatch".into());
        }
        Ok(Session {
            closed: self.closed.clone(),
        })
    }
}
pub fn retired(
    runtime: Arc<agent_locksmith::native::Runtime>,
    closed: CancellationToken,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // One session in this fixture. Released means the actual manager has
            // completed both worker joins, stronger than a cancellation signal.
            if runtime.snapshot().released > 0 {
                closed.cancel();
                return;
            }
            tokio::select! { _=stop.cancelled()=>return,
            _=tokio::time::sleep(std::time::Duration::from_millis(5))=>{} }
        }
    })
}
