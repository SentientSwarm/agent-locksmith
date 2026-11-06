use super::{Error, Result};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Control {
    pub request: CancellationToken,
    pub session: CancellationToken,
    pub deadline: Instant,
}
impl Control {
    pub fn check(&self) -> Result<()> {
        if self.request.is_cancelled() || self.session.is_cancelled() {
            Err(Error("request_cancelled"))
        } else if Instant::now() >= self.deadline {
            Err(Error("operation_deadline"))
        } else {
            Ok(())
        }
    }
    pub async fn run<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        tokio::select! {
            biased;
            _ = self.request.cancelled() => Err(Error("request_cancelled")),
            _ = self.session.cancelled() => Err(Error("request_cancelled")),
            _ = tokio::time::sleep_until(self.deadline) => Err(Error("operation_deadline")),
            value = work => value,
        }
    }
}
