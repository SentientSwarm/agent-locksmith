use super::super::{config, contract_tests, token};
use serde_json::{Value, json};

fn profile(slack: bool) -> config::Profile {
    let mut value = contract_tests::declared(false);
    if slack {
        value["contract"]["token_response"] = json!("slack-user-v2");
    }
    serde_json::from_value(value).unwrap()
}
fn refused(slack: bool, value: &Value) -> &'static str {
    token::decode(&profile(slack), &serde_json::to_vec(value).unwrap())
        .err()
        .expect("every error shape must refuse")
        .0
}
#[test]
fn contract_token_refusal_explicit_verifier_is_closed() {
    for slack in [false, true] {
        for value in [
            json!({"error":"bad_code_verifier"}),
            json!({"ok":false,"error":"bad_code_verifier"}),
        ] {
            assert_eq!(refused(slack, &value), "token_verifier_refused");
        }
    }
}
#[test]
fn contract_token_refusal_generic_and_contaminated_stays_unknown() {
    let cases = [
        json!({"error":"invalid_code"}),
        json!({"error":"invalid_grant"}),
        json!({"error":"private-canary"}),
        json!({"error":null}),
        json!({"error":7}),
        json!({"error":"bad_code_verifier","error_description":"private-canary"}),
        json!({"error":"bad_code_verifier","error_uri":"https://private.invalid/"}),
        json!({"error":"bad_code_verifier","extra":"private-canary"}),
        json!({"error":"bad_code_verifier","access_token":"private-canary"}),
        json!({"error":"bad_code_verifier","ok":true}),
    ];
    for slack in [false, true] {
        for value in &cases {
            assert_eq!(refused(slack, value), "token_response_refused");
        }
        assert_eq!(
            token::decode(
                &profile(slack),
                br#"{"error":"bad_code_verifier","error":"bad_code_verifier"}"#
            )
            .err()
            .unwrap()
            .0,
            "json_refused"
        );
    }
}

#[test]
fn contract_token_refusal_known_secret_cannot_be_specific() {
    use super::super::token_io;
    for slack in [false, true] {
        for known in ["bad_code_verifier", "code", "error"] {
            for bytes in [
                br#"{"error":"bad_code_verifier"}"#.as_slice(),
                br#"{"error":"bad_code_verifi\u0065r"}"#.as_slice(),
            ] {
                let error = token_io::checked_decode(&profile(slack), bytes, Some(known))
                    .err()
                    .unwrap();
                assert_eq!(error.0, "token_response_refused");
                assert_eq!(
                    token_io::exchange_status(
                        &profile(slack),
                        reqwest::StatusCode::BAD_REQUEST,
                        bytes,
                        Some(known)
                    )
                    .err()
                    .unwrap()
                    .0,
                    "token_http_refused"
                );
            }
        }
    }
}
