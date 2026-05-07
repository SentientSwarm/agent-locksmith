//! T3.9 / #68 — audit-write throughput bench.
//!
//! Validates A-2 / INF-26 — "~1000 sustained writes/sec on commodity SSD".
//! Run with `cargo bench --bench audit_write_bench`.
//!
//! What it measures:
//! - Single-writer mean per-record latency (steady-state).
//! - 1, 10, 100 concurrent writers, throughput at each fan-out.
//!
//! What it does NOT measure:
//! - JSONL fan-out overhead (separate concern; sink is opt-in).
//! - Cross-process contention (single-process benches; multi-tenant is
//!   out of scope per A-2 single-instance posture).
//!
//! Output: criterion's HTML reports under `target/criterion/`. The
//! INF-26 trigger is p95 > 5ms under sustained 1000 writes/sec; that's
//! checked from the criterion result by inspecting the
//! `concurrent_writers/100` benchmark's per-record latency × concurrency.

use std::sync::Arc;

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;
use tokio::runtime::Runtime;

fn build_event(idx: u64) -> AuditEvent {
    AuditEvent {
        ts_ms: 1_750_000_000_000 + idx as i64,
        event_class: EventClass::Proxy,
        event: "proxy_request".to_string(),
        agent_public_id: Some(format!("ag_{idx:08}")),
        agent_name: None,
        operator_name: None,
        tool: Some("openai".to_string()),
        upstream_host: Some("api.openai.com".to_string()),
        method: Some("POST".to_string()),
        path: Some("/v1/chat/completions".to_string()),
        status: Some(200),
        latency_ms: Some(45),
        decision: Decision::Allowed,
        auth_method: Some("bearer".to_string()),
        origin_ip: None,
        details: None,
    }
}

async fn fresh_audit() -> (TempDir, AuditRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    (dir, audit)
}

fn bench_single_writer(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (_dir, audit) = rt.block_on(fresh_audit());
    let mut group = c.benchmark_group("single_writer");
    group.throughput(Throughput::Elements(1));
    group.bench_function("record", |b| {
        let mut counter: u64 = 0;
        b.to_async(&rt).iter(|| {
            let audit = audit.clone();
            counter = counter.wrapping_add(1);
            let event = build_event(counter);
            async move {
                audit.record(&event).await.expect("record ok");
            }
        });
    });
    group.finish();
}

fn bench_concurrent_writers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_writers");
    for &concurrency in &[1usize, 10, 100] {
        let (_dir, audit) = rt.block_on(fresh_audit());
        let audit = Arc::new(audit);
        // Each iteration: emit `concurrency` records in parallel.
        // criterion reports per-iteration latency; per-record latency
        // = iter_latency / concurrency, throughput = concurrency / iter_latency.
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("record_batch", concurrency),
            &concurrency,
            |b, &n| {
                let mut counter: u64 = 0;
                b.to_async(&rt).iter(|| {
                    let audit = audit.clone();
                    counter = counter.wrapping_add(1);
                    let base = counter.wrapping_mul(n as u64);
                    async move {
                        let mut handles = Vec::with_capacity(n);
                        for i in 0..n {
                            let audit = audit.clone();
                            let event = build_event(base + i as u64);
                            handles.push(tokio::spawn(async move {
                                audit.record(&event).await.expect("record ok");
                            }));
                        }
                        for h in handles {
                            h.await.unwrap();
                        }
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .measurement_time(std::time::Duration::from_secs(8));
    targets = bench_single_writer, bench_concurrent_writers
}
criterion_main!(benches);
