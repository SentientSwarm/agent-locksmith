use super::*;
pub(super) async fn run() {
    let prior = std::env::var("LOCKSMITH_CONTRACT_PRIOR_DAEMON").unwrap();
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let up = receiver::Receiver::start(&f);
    write(&f, "manifest.json", tools());
    config(&f, Some("finite-v2"));
    f.start(process::DAEMON).await;
    let a = f.enroll("old-reader", &format!("https://localhost:{}/mcp", up.port));
    let id = a["public_id"].as_str().unwrap();
    grant_policy(&f, id);
    f.stop();
    refuse_old(&f, &prior);
    assert!(f.http.get(f.url("/livez")).send().await.is_err());
    f.start(process::DAEMON).await;
    assert_eq!(flow::show(&f, id)["callable"], false);
    flow::observe(&f, id);
    standard(&f, a["token"].as_str().unwrap()).await;
    f.stop();
    up.stop();
}
fn refuse_old(f: &fixture::Fixture, prior: &str) {
    let log = std::fs::File::create(f.path().join("old.log")).unwrap();
    let mut c = process::command(prior);
    c.arg("--config")
        .arg(f.path().join("config.yaml"))
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut child = process::Guard(c.spawn().unwrap());
    assert!(!process::wait(&mut child.0).success());
}
