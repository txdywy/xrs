# xrs

`xrs` is a Rust reimplementation of Xray-core, built incrementally around an Xray-compatible configuration surface and a Rust-native async runtime.

Current milestone:

- Workspace crates for common models, config, routing, observability, core runtime, and CLI.
- JSON config loading for a minimal Xray-like subset.
- SOCKS5 and HTTP CONNECT inbound TCP handling.
- `freedom` and `blackhole` outbound behavior.
- Static routing by inbound tag and destination port.

The long-term goal is functional parity with Xray-core, including protocol, transport, security, DNS, stats/API, and multi-platform release workflows.
