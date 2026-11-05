use super::tests::{context, snapshot};
use crate::native::{
    compact::{self, Prepared},
    context::Context,
};
use crate::native_authority::{
    Error, Result,
    control::Control,
    effective::{Approved, Snapshot},
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

fn tool(name: &str) -> Approved {
    let public = json!({"name":name,"description":"Read a record","inputSchema":{"type":"object","properties":{"key":{"type":"string"}},"required":["key"],"additionalProperties":false}});
    Approved {
        digest: format!("{:064x}", name.bytes().map(u64::from).sum::<u64>()),
        effect: "mixed".into(),
        tool: public.clone(),
        public,
        context: Default::default(),
    }
}
fn inventory() -> Snapshot {
    let mut s = snapshot();
    s.observed_at = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    );
    s.generation = Some("generation".into());
    s.revision = Some("revision".into());
    for name in ["read_a", "read_b"] {
        s.tools.insert(name.into(), tool(name));
    }
    s
}
fn control() -> Control {
    Control {
        request: CancellationToken::new(),
        session: CancellationToken::new(),
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(10),
    }
}
fn local(c: &Context, s: &Snapshot, name: &str, args: Value) -> Result<Value> {
    match compact::prepare(c, s, name, args, &control())? {
        Prepared::Local(v) => {
            Ok(serde_json::from_str(v["content"][0]["text"].as_str().unwrap()).unwrap())
        }
        _ => panic!("unexpected dispatch"),
    }
}
fn search(c: &Context, s: &Snapshot) -> Value {
    local(c, s, "search", json!({"query":"read","limit":1})).unwrap()
}
fn invoke(c: &Context, s: &Snapshot, e: &Value) -> Result<Prepared> {
    compact::prepare(
        c,
        s,
        "invoke",
        json!({"handle":e["handle"],"contract_digest":e["contract_digest"],"arguments":{"key":"record"}}),
        &control(),
    )
}
fn reason<T>(r: Result<T>) -> &'static str {
    match r {
        Err(Error(s)) => s,
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn first_empty_pin_and_separate_describe_receipt() {
    let c = context();
    let s = inventory();
    assert_eq!(
        reason(local(&c, &s, "search", json!({"query":"read"}))),
        "tools_list_required"
    );
    compact::list(&c, &s).unwrap();
    let e = search(&c, &s)["matches"][0].clone();
    assert_eq!(reason(invoke(&c, &s, &e)), "schema_required");
    let d = local(&c, &s, "describe", json!({"handle":e["handle"]})).unwrap();
    assert_eq!(d["input_schema"], s.tools["read_a"].public["inputSchema"]);
    assert_eq!(d["effect"], "mixed");
    assert!(matches!(invoke(&c, &s, &e), Ok(Prepared::Invoke(_))));
    let other = context();
    compact::list(&other, &s).unwrap();
    assert_eq!(
        reason(local(&other, &s, "describe", json!({"handle":e["handle"]}))),
        "compact_reference"
    );
    let empty = context();
    compact::list(&empty, &snapshot()).unwrap();
    assert_eq!(search(&empty, &s)["matches"], json!([]));
}
#[test]
fn cursor_bytes_revision_and_handle_lifetimes_are_distinct() {
    let c = context();
    let mut s = inventory();
    compact::list(&c, &s).unwrap();
    let first = search(&c, &s);
    let e = &first["matches"][0];
    local(&c, &s, "describe", json!({"handle":e["handle"]})).unwrap();
    for (query, limit) in [("READ", 1), (" read", 1), ("read", 2)] {
        assert_eq!(
            reason(local(
                &c,
                &s,
                "search",
                json!({"query":query,"limit":limit,"cursor":first["next_cursor"]})
            )),
            "compact_cursor_changed"
        );
    }
    let next = local(
        &c,
        &s,
        "search",
        json!({"query":"read","limit":1,"cursor":first["next_cursor"]}),
    )
    .unwrap();
    assert_eq!(next["matches"][0]["name"], "read_b");
    assert_eq!(search(&c, &s), first);
    s.revision = Some("exact-regrant".into());
    assert!(matches!(invoke(&c, &s, e), Ok(Prepared::Invoke(_))));
    assert_eq!(
        reason(local(
            &c,
            &s,
            "search",
            json!({"query":"read","limit":1,"cursor":first["next_cursor"]})
        )),
        "compact_cursor_changed"
    );
    s.tools.remove("read_a");
    assert_eq!(reason(invoke(&c, &s, e)), "compact_reference");
}
#[test]
fn bounded_atomic_registry_keeps_prior_receipts_on_failure() {
    let c = context();
    let mut s = inventory();
    compact::list(&c, &s).unwrap();
    let first = search(&c, &s);
    let e = &first["matches"][0];
    local(&c, &s, "describe", json!({"handle":e["handle"]})).unwrap();
    for n in 0..31 {
        let q = format!("{}read", " ".repeat(n + 1));
        local(&c, &s, "search", json!({"query":q,"limit":1})).unwrap();
    }
    let before = c.compact.lock().unwrap().clone();
    assert_eq!(
        reason(local(&c, &s, "search", json!({"query":"READ","limit":1}))),
        "compact_capacity"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
    assert!(matches!(invoke(&c, &s, e), Ok(Prepared::Invoke(_))));
    // Failed encoding must not publish a newly found handle or erase prior receipts.
    s.tools.get_mut("read_b").unwrap().public["inputSchema"]["properties"] =
        json!({"huge":{"type":"string","description":"x".repeat(17000)}});
    let selected = local(&c, &s, "search", json!({"query":"read_b"})).unwrap();
    let b = &selected["matches"][0];
    let before = c.compact.lock().unwrap().clone();
    assert_eq!(
        reason(local(&c, &s, "describe", json!({"handle":b["handle"]}))),
        "compact_response_limit"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
    assert_eq!(reason(invoke(&c, &s, b)), "schema_required");
    assert!(matches!(invoke(&c, &s, e), Ok(Prepared::Invoke(_))));
}
#[test]
fn cancellation_before_publication_and_signature_quoting() {
    let c = context();
    let mut s = inventory();
    let name = "odd\": string optional, (";
    s.tools.get_mut("read_a").unwrap().public["inputSchema"] = json!({"type":"object","properties":{name:{"type":"object","properties":{},"additionalProperties":false}},"required":[name],"additionalProperties":false});
    compact::list(&c, &s).unwrap();
    let before = c.compact.lock().unwrap().clone();
    let ctrl = control();
    ctrl.request.cancel();
    assert_eq!(
        reason(compact::prepare(
            &c,
            &s,
            "search",
            json!({"query":"read"}),
            &ctrl
        )),
        "request_cancelled"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
    let result = search(&c, &s);
    assert_eq!(
        result["matches"][0]["signature"],
        format!("({}: object required)", json!(name))
    );
}
#[test]
fn wrapper_refuses_unknown_null_type_and_unbounded_input() {
    let c = context();
    let s = inventory();
    compact::list(&c, &s).unwrap();
    for v in [
        json!({}),
        json!({"query":" "}),
        json!({"query":"x\n"}),
        json!({"query":"é".repeat(129)}),
        json!({"query":"x","limit":0}),
        json!({"query":"x","limit":1.0}),
        json!({"query":"x","limit":null}),
        json!({"query":"x","cursor":null}),
        json!({"query":"x","extra":1}),
    ] {
        assert_eq!(reason(local(&c, &s, "search", v)), "compact_arguments");
    }
    for v in [
        json!({"handle":"a".repeat(32),"extra":1}),
        json!({"handle":"A".repeat(32)}),
        json!({"handle":null}),
    ] {
        assert_eq!(reason(local(&c, &s, "describe", v)), "compact_arguments");
    }
}
#[test]
fn concurrent_search_and_describe_preserve_the_same_receipt() {
    let c = std::sync::Arc::new(context());
    let s = inventory();
    compact::list(&c, &s).unwrap();
    let first = search(&c, &s);
    let e = first["matches"][0].clone();
    std::thread::scope(|scope| {
        for n in 0..16 {
            let c = &c;
            let s = &s;
            let e = &e;
            let first = &first;
            scope.spawn(move || {
                if n % 2 == 0 {
                    assert_eq!(search(c, s), *first);
                } else {
                    local(c, s, "describe", json!({"handle":e["handle"]})).unwrap();
                }
            });
        }
    });
    assert!(matches!(invoke(&c, &s, &e), Ok(Prepared::Invoke(_))));
}

#[test]
fn standard_valid_schema_can_be_too_large_for_compact_describe() {
    let c = context();
    let mut s = inventory();
    let properties = (0..20)
        .map(|n| {
            (
                format!("field{n}"),
                json!({"type":"string","description":"d".repeat(1000)}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    s.tools.get_mut("read_a").unwrap().public["inputSchema"] =
        json!({"type":"object","properties":properties,"additionalProperties":false});
    crate::native_authority::contract::tool(&s.tools["read_a"].public).unwrap();
    compact::list(&c, &s).unwrap();
    let e = search(&c, &s)["matches"][0].clone();
    let before = c.compact.lock().unwrap().clone();
    assert_eq!(
        reason(local(&c, &s, "describe", json!({"handle":e["handle"]}))),
        "compact_response_limit"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
    assert_eq!(reason(invoke(&c, &s, &e)), "schema_required");
}

#[test]
fn upstream_facade_names_still_resolve_only_by_described_handle() {
    let c = context();
    let mut s = inventory();
    s.tools.clear();
    s.tools.insert("search".into(), tool("search"));
    compact::list(&c, &s).unwrap();
    let found = local(&c, &s, "search", json!({"query":"search"})).unwrap();
    let e = &found["matches"][0];
    local(&c, &s, "describe", json!({"handle":e["handle"]})).unwrap();
    let Prepared::Invoke(call) = invoke(&c, &s, e).unwrap() else {
        panic!("dispatcher invocation required")
    };
    assert_eq!(call.name, "search");
    s.expires_at = Some(1);
    let before = c.compact.lock().unwrap().clone();
    assert_eq!(
        reason(local(&c, &s, "search", json!({"query":"search"}))),
        "source_unavailable"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
}

#[test]
fn oversized_single_signature_publishes_no_new_handle() {
    let c = context();
    let mut s = inventory();
    let props = (0..127)
        .map(|n| {
            (
                format!("{n:03}{}", "x".repeat(125)),
                json!({"type":"string"}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    s.tools.get_mut("read_a").unwrap().public["inputSchema"] =
        json!({"type":"object","properties":props,"additionalProperties":false});
    crate::native_authority::contract::tool(&s.tools["read_a"].public).unwrap();
    compact::list(&c, &s).unwrap();
    let before = c.compact.lock().unwrap().clone();
    assert_eq!(
        reason(local(&c, &s, "search", json!({"query":"read_a","limit":1}))),
        "compact_response_limit"
    );
    assert_eq!(*c.compact.lock().unwrap(), before);
    assert_eq!(
        local(&c, &s, "search", json!({"query":"read_b"})).unwrap()["matches"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
