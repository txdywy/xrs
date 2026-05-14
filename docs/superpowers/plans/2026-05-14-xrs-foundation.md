# xrs Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable Rust proxy-core foundation for `xrs` with a minimal Xray-like config surface and local TCP proxy path.

**Architecture:** Use a Rust workspace with separate crates for common models, config, routing, observability, runtime, and CLI. The first vertical slice is `SOCKS5/HTTP CONNECT inbound -> SessionContext -> Router -> freedom/blackhole outbound -> TCP relay`.

**Tech Stack:** Rust 1.95, Tokio, Serde, Clap, Tracing, Thiserror, GitHub Actions.

---

## Implemented tasks

### Task 1: Workspace foundation

- [x] Create `Cargo.toml` workspace.
- [x] Create crates under `crates/`.
- [x] Add shared dependency versions and workspace lints.
- [x] Add `.gitignore`.

### Task 2: Common session model

- [x] Implement `DestinationHost`, `Destination`, `Network`, and `SessionContext` in `crates/xrs-common/src/lib.rs`.
- [x] Add normalization tests for IP/domain hosts.

### Task 3: Config baseline

- [x] Implement JSON config loading and validation in `crates/xrs-config/src/lib.rs`.
- [x] Support `socks` and `http` inbound protocols.
- [x] Support `freedom` and `blackhole` outbound protocols.
- [x] Reject missing inbounds/outbounds, unknown route targets, invalid ports, and duplicate tags.

### Task 4: Router baseline

- [x] Implement ordered first-match routing by inbound tag and destination port in `crates/xrs-router/src/lib.rs`.
- [x] Default to the first outbound when no rule matches.

### Task 5: Runtime baseline

- [x] Bind all listeners before reporting runtime startup success.
- [x] Implement SOCKS5 CONNECT parsing.
- [x] Implement HTTP CONNECT parsing.
- [x] Implement `freedom` outbound TCP connect and `blackhole` shutdown.
- [x] Add handshake/connect timeouts and per-inbound connection limit.

### Task 6: CLI and workflows

- [x] Implement `xrs run`, `xrs test`, `xrs version`, and `xrs uuid`.
- [x] Add CI workflow for fmt, clippy, tests.
- [x] Add initial multi-platform release workflow.

## Verification

- [x] `cargo fmt --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`
- [x] `cargo run --bin xrs -- test -c tests/fixtures/local-socks.json`
- [x] `cargo run --bin xrs -- version`

## Next tasks

### Task 7: End-to-end proxy integration tests

- [ ] Add local TCP echo server helper in `xrs-core` tests.
- [ ] Test SOCKS5 inbound reaches echo server through freedom outbound.
- [ ] Test HTTP CONNECT inbound reaches echo server through freedom outbound.
- [ ] Test blackhole route closes blocked connections.

### Task 8: Xray config compatibility improvements

- [ ] Prefer `inboundTag` while accepting `inbound_tag` as compatibility alias.
- [ ] Add `xrs test` fixture using Xray-style camelCase route fields.
- [ ] Add config dump command.

### Task 9: Phase 2 planning

- [ ] Define accepted-but-unsupported top-level Xray config sections.
- [ ] Add multi-file and confdir loading plan.
- [ ] Add golden config corpus structure.
