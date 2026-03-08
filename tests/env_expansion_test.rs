use secure_agent_proxy::config::expand_env_vars;

#[test]
fn test_expand_single_var() {
    unsafe { std::env::set_var("TEST_SAP_TOKEN", "secret123") };
    let result = expand_env_vars("Bearer ${TEST_SAP_TOKEN}");
    assert_eq!(result, "Bearer secret123");
    unsafe { std::env::remove_var("TEST_SAP_TOKEN") };
}

#[test]
fn test_expand_missing_var_empty() {
    let result = expand_env_vars("Bearer ${NONEXISTENT_VAR_12345}");
    assert_eq!(result, "Bearer ");
}

#[test]
fn test_no_vars_passthrough() {
    let result = expand_env_vars("plain-value");
    assert_eq!(result, "plain-value");
}

#[test]
fn test_expand_multiple_vars() {
    unsafe { std::env::set_var("TEST_SAP_A", "aaa") };
    unsafe { std::env::set_var("TEST_SAP_B", "bbb") };
    let result = expand_env_vars("${TEST_SAP_A}-${TEST_SAP_B}");
    assert_eq!(result, "aaa-bbb");
    unsafe { std::env::remove_var("TEST_SAP_A") };
    unsafe { std::env::remove_var("TEST_SAP_B") };
}
