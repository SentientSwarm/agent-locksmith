use agent_locksmith::oauth::refresh::RefreshOwner;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn closure_drops_whole_scope_before_wait_returns() {
    let owner = RefreshOwner::default();
    let dropped = Arc::new(AtomicUsize::new(0));
    let (started, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn({
        let owner = owner.clone();
        let dropped = dropped.clone();
        async move {
            owner
                .run(async move {
                    let _lease = Lease(dropped);
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                    panic!("canceled cleanup must not execute");
                })
                .await
        }
    });
    observed.await.unwrap();
    owner.close();
    tokio::time::timeout(std::time::Duration::from_secs(1), owner.wait())
        .await
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(task.await.unwrap().is_none());
    refused(&owner).await;
}

#[tokio::test]
async fn aborted_caller_releases_ownership_and_waiter_cancel_does_not_reopen() {
    let owner = RefreshOwner::default();
    let task = tokio::spawn({
        let owner = owner.clone();
        async move { owner.run(std::future::pending::<()>()).await }
    });
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    owner.close();
    let wait = tokio::spawn({
        let owner = owner.clone();
        async move { owner.wait().await }
    });
    wait.abort();
    let _ = wait.await;
    owner.wait().await;
    assert!(owner.run(async { 1 }).await.is_none());
}

async fn refused(owner: &RefreshOwner) {
    assert!(
        owner
            .run(async { panic!("closed admission polled") })
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_close_and_registration_release_every_admitted_scope() {
    let owner = RefreshOwner::default();
    let entered = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut tasks = Vec::new();
    for _ in 0..64 {
        tasks.push(contend(
            owner.clone(),
            entered.clone(),
            dropped.clone(),
            barrier.clone(),
        ));
    }
    barrier.wait().await;
    owner.close();
    for task in tasks {
        assert!(task.await.unwrap().is_none());
    }
    owner.wait().await;
    assert_eq!(
        entered.load(Ordering::SeqCst),
        dropped.load(Ordering::SeqCst)
    );
    refused(&owner).await;
}

fn contend(
    owner: RefreshOwner,
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    barrier: Arc<tokio::sync::Barrier>,
) -> tokio::task::JoinHandle<Option<()>> {
    tokio::spawn(async move {
        barrier.wait().await;
        owner
            .run(async move {
                entered.fetch_add(1, Ordering::SeqCst);
                let _lease = Lease(dropped);
                std::future::pending::<()>().await;
            })
            .await
    })
}
