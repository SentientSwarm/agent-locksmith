//! D1.1: real auth/SQLite/proxy; only external upstream accounts are simulated.
#[path = "account_bindings/application.rs"]
mod application;
#[path = "account_bindings/assertions.rs"]
mod assertions;
#[path = "account_bindings/failures.rs"]
mod failures;
#[path = "account_bindings/fixture.rs"]
mod fixture;
#[path = "account_bindings/guidance.rs"]
mod guidance;
#[path = "account_bindings/lifecycle.rs"]
mod lifecycle;
#[path = "account_bindings/logs.rs"]
mod logs;
