//! Test-only lifetime acknowledgement; never compiled into shipping binaries.
use axum::extract::Request;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Probe {
    pub entered: AtomicUsize,
    pub dropped: AtomicUsize,
    pub forced: AtomicUsize,
    pub aborted: AtomicUsize,
    changed: Notify,
}
type Registry = Mutex<HashMap<String, Weak<Probe>>>;
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
pub(crate) fn register(key: &str) -> Arc<Probe> {
    let probe = Arc::new(Probe::default());
    assert!(
        registry()
            .lock()
            .unwrap()
            .insert(key.into(), Arc::downgrade(&probe))
            .is_none()
    );
    probe
}
pub(crate) fn remove(key: &str) {
    registry().lock().unwrap().remove(key);
}
fn lookup(key: &str) -> Option<Arc<Probe>> {
    registry().lock().unwrap().get(key).and_then(Weak::upgrade)
}
pub(crate) struct Lease(Arc<Probe>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, SeqCst);
        self.0.changed.notify_waiters();
    }
}
pub(crate) fn enter(request: &Request) -> Option<Lease> {
    let key = request.headers().get("x-native-body-test")?.to_str().ok()?;
    let p = lookup(key)?;
    p.entered.fetch_add(1, SeqCst);
    p.changed.notify_waiters();
    Some(Lease(p))
}
impl Probe {
    pub async fn entered(&self) {
        loop {
            let changed = self.changed.notified();
            if self.entered.load(SeqCst) != 0 {
                return;
            }
            changed.await;
        }
    }
}
pub(crate) async fn hold_listener(path: PathBuf, transport: &'static str) {
    if let Some(p) = lookup(&format!("{}:{transport}", path.display())) {
        let _held = Held(p.clone());
        p.forced.fetch_add(1, SeqCst);
        std::future::pending::<()>().await;
    }
}
struct Held(Arc<Probe>);
impl Drop for Held {
    fn drop(&mut self) {
        self.0.aborted.fetch_add(1, SeqCst);
    }
}
