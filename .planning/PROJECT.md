# xrs Project

`xrs` is a Rust reimplementation of Xray-core. The project targets staged functional parity with Xray-core while using a Rust-native async architecture for stability, safety, and performance.

## Objectives

- Preserve the Xray-style JSON configuration surface where practical.
- Build a modular proxy runtime with reusable inbound, routing, outbound, transport, security, DNS, stats, and API layers.
- Add protocol parity incrementally, with compatibility tests against known protocol behavior and later against Xray-core subprocesses.
- Ship reproducible multi-platform release archives through GitHub Actions.

## Current milestone

Milestone 0/1 foundation is active:

- Rust workspace and crate boundaries.
- CLI with `run`, `test`, `version`, and `uuid`.
- Minimal config parser and validator.
- Static router by inbound tag and destination port.
- SOCKS5 and HTTP CONNECT inbound TCP handling.
- `freedom` and `blackhole` outbound behavior.
- Basic traffic counters.
- CI and release workflow skeletons.

## Compatibility posture

Unsupported Xray protocols and advanced config sections should fail explicitly until implemented. Silent acceptance of unsupported config is not allowed.
