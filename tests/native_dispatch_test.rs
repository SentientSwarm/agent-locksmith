#![allow(dead_code)] // Shared historical fixture helpers cover other targets.
#[path = "native/fixture.rs"]
mod native;
#[path = "native_dispatch/pins.rs"]
mod pins;
#[path = "native_preparation/support.rs"]
mod support;
#[path = "native_dispatch/validation.rs"]
mod validation;
