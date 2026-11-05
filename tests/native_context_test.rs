#![allow(dead_code)] // Existing shared setup also serves preparation tests.
#[path = "native_context/diagnostics.rs"]
mod diagnostics;
#[path = "native/fixture.rs"]
mod native;
#[path = "native_context/review.rs"]
mod review;
#[path = "native_preparation/support.rs"]
mod support;
#[path = "native_context/values.rs"]
mod values;

#[path = "native_context/limits.rs"]
mod limits;
#[path = "native_context/storage.rs"]
mod storage;
