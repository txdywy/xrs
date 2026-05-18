# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`xrs` is a Rust reimplementation of Xray-core, built incrementally around an Xray-compatible JSON configuration surface and a Rust-native async runtime. The long-term goal is functional parity with Xray-core across protocol, transport, security, DNS, stats/API, and multi-platform release workflows.

The workspace uses Rust 2024, requires Rust 1.95, is licensed MPL-2.0, forbids unsafe code, and denies all Clippy warnings.

## Common commands

- Format check: `cargo fmt --check`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Test workspace: `cargo test --workspace`
- Test with lockfile: `cargo test --locked`
- Run a single test by name: `cargo test --workspace <test_name>`
- Build workspace: `cargo build --workspace`
- Release build for the current target: `cargo build --release --locked`
- Run the CLI: `cargo run -p xrs-bin -- <command>`
- Validate config through the CLI: `cargo run -p xrs-bin -- test -c <config.json>`
- Dump normalized config through the CLI: `cargo run -p xrs-bin -- dump -c <config.json>`

The CI workflow runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`; the release workflow builds locked release artifacts for configured Linux, macOS, and Windows targets.

## Architecture

This is a Cargo workspace with six crates:

- `crates/xrs-common`: shared domain types such as `Destination`, `DestinationHost`, `Network`, and `SessionContext`. Keep this crate small, dependency-light, and protocol-neutral.
- `crates/xrs-config`: Xray-compatible JSON config schema, config-file/confdir loading, multi-file merging, and validation of supported versus unsupported config fields. This is the compatibility boundary for accepting, defaulting, or rejecting Xray config shapes.
- `crates/xrs-router`: pure routing engine. It builds `Router` from `RootConfig` and maps `SessionContext` to outbound tags using routing rules, balancers, domain strategy, and matchers. Keep it I/O-free.
- `crates/xrs-observability`: traffic counter primitives used by runtime policy/stat handling.
- `crates/xrs-core`: async runtime and protocol implementation. It owns listeners, inbound/outbound handling, session sniffing, DNS behavior, socket options, traffic counters, and TCP/UDP relay paths.
- `crates/xrs-bin`: CLI binary `xrs`. It parses commands and compatibility aliases, initializes tracing, loads config through `xrs-config`, and starts `xrs_core::Runtime`.

Dependency flow is intentionally layered:

```text
xrs-bin -> xrs-config, xrs-core
xrs-core -> xrs-common, xrs-config, xrs-router, xrs-observability
xrs-router -> xrs-common, xrs-config
xrs-config -> xrs-common
xrs-observability -> no workspace crate dependencies
xrs-common -> no workspace crate dependencies
```

Conceptually, JSON config becomes `xrs_config::RootConfig`; `xrs-core` validates and turns that into runtime state; `xrs-router` chooses outbound tags from `xrs_common::SessionContext`; `xrs-observability` tracks counters used by the runtime.

## Development guidance

- Preserve crate boundaries: CLI behavior belongs in `xrs-bin`, config compatibility and validation in `xrs-config`, routing policy in `xrs-router`, and network/protocol I/O in `xrs-core`.
- When adding Xray-core parity, usually model and validate the config surface in `xrs-config` before wiring runtime behavior in `xrs-core`.
- Keep routing semantics centralized in `xrs-router`; `xrs-core` should enrich `SessionContext` and ask the router rather than duplicating rule matching.
- Keep `xrs-router` deterministic apart from explicitly configured randomized balancer strategies, and avoid adding network or filesystem access there.
- `crates/xrs-core/src/lib.rs` is currently the large runtime/protocol hub; make focused changes and consider extracting protocol-specific modules only when a change is substantial enough to justify it.
- Existing config fixtures live under `tests/fixtures`; prefer them when testing config loading, merging, and compatibility behavior.
