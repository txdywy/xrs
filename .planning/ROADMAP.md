# xrs Roadmap

## Phase 0: Workspace and runtime foundation

- Workspace crates: common, config, router, observability, core, CLI.
- Config validation for supported subset.
- TCP runtime with listener startup failure reporting.
- SOCKS5 and HTTP CONNECT inbound.
- Freedom and blackhole outbound.
- Unit tests and CLI smoke tests.

## Phase 1: Local proxy hardening

- End-to-end local echo integration tests for SOCKS5 and HTTP CONNECT.
- Graceful shutdown test harness.
- Config loading parity improvements: `inboundTag`, `outboundTag`, default config path, config dump.
- Better HTTP authority parsing including bracketed IPv6.
- Policy-configurable handshake/connect/idle timeouts.

## Phase 2: Config compatibility baseline

- Add top-level Xray sections as typed accepted/explicitly unsupported structures.
- Multi-file and confdir loading.
- `run -test`/`-dump` compatibility aliases.
- Golden config corpus from Xray examples.

## Phase 3: Additional TCP protocols

- Shadowsocks AEAD TCP inbound/outbound.
- Trojan TCP inbound/outbound.
- VLESS TCP inbound/outbound.
- VMess AEAD TCP inbound/outbound.

## Phase 4: Security and transports

- TLS with rustls.
- WebSocket transport.
- gRPC and HTTPUpgrade.
- REALITY/XTLS/Vision compatibility research and implementation.

## Phase 5: DNS, UDP, and routing parity

- DNS resolver and cache.
- Domain/IP routing rules.
- SOCKS UDP and UDP relay abstraction.
- Dokodemo-door inbound.
- GeoIP/GeoSite loaders.

## Phase 6: API, metrics, release parity

- Stats API and Prometheus metrics.
- GitHub Actions release matrix expansion.
- Archive checksums and SBOM.
- Docker packaging.
