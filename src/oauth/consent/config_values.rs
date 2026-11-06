pub(super) fn managed_kind(kind: &str) -> bool {
    matches!(
        kind,
        "controlled_linear_v1"
            | "linear_hosted_v1"
            | "linear_hosted_fixture_v1"
            | "slack_confidential_v1"
            | "slack_confidential_fixture_v1"
    )
}
pub(super) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
