//! Build-time Git qualification, not signing or a runtime environment assertion.

pub fn document(name: &str) -> serde_json::Value {
    let revision = env!("LOCKSMITH_BUILD_REVISION");
    serde_json::json!({
        "name": name,
        "version": env!("CARGO_PKG_VERSION"),
        "build": {
            "revision": if revision.is_empty() { None } else { Some(revision) },
            "source_state": env!("LOCKSMITH_BUILD_SOURCE_STATE"),
        },
    })
}
