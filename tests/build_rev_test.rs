// The build script's own `#[cfg(test)] mod tests` is never executed by `cargo test`, so the module is pulled into a test crate here; the tests themselves live beside the code, as everywhere else in this crate.
#[path = "../build_rev.rs"]
mod build_rev;
