use super::*;
use crate::{
    native_authority::{effective::Approved, source::Current},
    registrations::{AuthSpec, Kind, Registration, admission::HttpAdmission},
};
use serde_json::json;

pub(super) fn context() -> Context {
    Context::new(
        Weak::new(),
        AgentIdentity {
            id: 1,
            public_id: "agent".into(),
            name: "agent".into(),
            tool_allowlist: None,
            tool_denylist: None,
        },
        "native".into(),
        Scope {
            owner: "agent".into(),
            connection: "native".into(),
            authority: super::super::scope::authority("instance", 2, 3),
        },
        CancellationToken::new(),
    )
}
fn admission() -> HttpAdmission {
    HttpAdmission {
        registration: Registration::new(
            "native".into(),
            Kind::Tool,
            String::new(),
            "https://example.test/mcp".into(),
            AuthSpec::None,
        ),
        account: Some(AuthSpec::None),
        agent_active: true,
        grant: Ok(()),
        instance: "instance".into(),
        revision: 2,
        epoch: 3,
    }
}
pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        current: Current {
            source: authority::source::Source {
                instance: "instance".into(),
                revision: 2,
                agent_epoch: 3,
                account_key: "account".into(),
            },
            agent: 1,
            admission: admission(),
            controlled: None,
        },
        generation: None,
        revision: None,
        observed_at: None,
        expires_at: None,
        tools: Default::default(),
    }
}
#[test]
fn first_list_refuses_a_new_snapshot_in_an_old_session() {
    for nonempty in [false, true] {
        for field in ["instance", "revision", "epoch", "owner", "connection"] {
            let mut context = context();
            let mut snapshot = snapshot();
            if nonempty {
                snapshot.tools.insert(
                    "one".into(),
                    Approved {
                        digest: "digest".into(),
                        effect: "read".into(),
                        tool: json!({"name":"one"}),
                        public: json!({"name":"one"}),
                        context: Default::default(),
                    },
                );
            }
            match field {
                "instance" => snapshot.current.source.instance = "replacement".into(),
                "revision" => snapshot.current.source.revision += 1,
                "epoch" => snapshot.current.source.agent_epoch += 1,
                "owner" => context.scope.owner = "other".into(),
                _ => context.scope.connection = "other".into(),
            }
            assert_eq!(context.list(&snapshot).unwrap_err().0, "authority_changed");
            assert!(context.cancelled.is_cancelled());
            assert!(context.pins.lock().unwrap().0.is_none());
        }
    }
}
#[test]
fn matching_empty_list_pins_and_later_scope_change_retires() {
    let context = context();
    let mut snapshot = snapshot();
    assert!(context.list(&snapshot).unwrap().is_empty());
    let original = context.pins.lock().unwrap().0.clone();
    assert!(original.is_some());
    snapshot.current.source.agent_epoch += 1;
    assert_eq!(context.list(&snapshot).unwrap_err().0, "authority_changed");
    assert!(context.cancelled.is_cancelled());
    assert_eq!(context.pins.lock().unwrap().0, original);
}
