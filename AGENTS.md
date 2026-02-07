# AGENTS.md (hosts-dns-forwarder)

This repository contains `hosts-dns-forwarder`, a tiny UDP DNS server.

- Behavior: answer from `/etc/hosts` (A/AAAA/ANY) first; otherwise forward the raw DNS packet to upstream(s).
- Scope: intentionally minimal (UDP-only; no TCP fallback, no caching, no DNSSEC).
- Runtime: async Rust (`tokio`) + DNS codec (`trust-dns-proto`) + errors (`anyhow`).

Rules files:
- Cursor: none (`.cursor/rules/` and `.cursorrules` are not present)
- Copilot: none (`.github/copilot-instructions.md` is not present)

## Repo Layout

- `src/main.rs`: all server logic (single-file binary crate).
- `packaging/debian/`: build script + systemd unit + maint scripts for a local `.deb`.
- `README.md`: user-facing usage and packaging notes.

## Build / Lint / Test

```bash
# build
cargo build
cargo build --release

# format
cargo fmt
cargo fmt --all -- --check

# lint
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings

# tests
cargo test
cargo test -- --nocapture
```

Run a single test (important):

```bash
# by substring match
cargo test test_name_substring

# by fully-qualified name (when available)
cargo test module::tests::specific_test

# run a single integration test file (when tests/ exists)
cargo test --test integration_test_name
```

Manual verification (DNS):

```bash
# run on a non-privileged port
cargo run -- --listen 127.0.0.1:5300

# query it
dig @127.0.0.1 -p 5300 localhost A +short
dig @127.0.0.1 -p 5300 google.com A +short
```

Debian/Ubuntu packaging (local .deb):

```bash
bash packaging/debian/build-deb.sh
dpkg-deb -I dist/*.deb
dpkg-deb -c dist/*.deb
```

## Code Style Guidelines

Rust edition / MSRV:
- Edition is 2021.
- Try to keep compatibility with Rust 1.78; be cautious with `cargo update`.

Imports:
- Group by crate: `std` first, then external crates, then local modules.
- Keep imports tight; avoid `use crate::*`.

Formatting:
- Always run `cargo fmt` before committing.
- Prefer readable code; let rustfmt wrap long match arms/strings.

Naming:
- Types: `PascalCase` (`Config`).
- Functions/vars: `snake_case` (`load_hosts_map`, `forward_udp_once`).
- Constants: `SCREAMING_SNAKE_CASE` (`MAX_DNS_PACKET`).

Types / data modeling:
- Prefer `SocketAddr`, `IpAddr`, `Duration`, `PathBuf` over raw strings.
- DNS packets are binary: keep buffers as `Vec<u8>`; avoid copies unless needed.

Error handling:
- Use `anyhow::Result` at the binary boundary; add context via `.context(...)` / `.with_context(...)`.
- Use `bail!(...)` for early exits.
- Never panic on malformed network input.
- On upstream failures, reply `SERVFAIL` (see `forward_and_reply`).

Async / tokio:
- Do not block the runtime thread; prefer `tokio::fs`, `tokio::net`, `tokio::time`.
- Per-packet `tokio::spawn` is acceptable, but keep per-request work small.

DNS behavior (keep consistent):
- Preserve request id and echo the query section.
- If EDNS is present in the request, include it in the response.
- `/etc/hosts` answers are authoritative (`AA=1`).
- If name exists in `/etc/hosts` but type does not match: `NOERROR` with empty answer (NODATA).
- Forwarding path forwards the *raw packet* to upstream and returns upstream raw response.

Minimalism policy:
- Prefer small, obvious code over feature-rich frameworks.
- Avoid heavy dependencies unless required.
- Defaults should be safe/non-conflicting: `127.0.0.1:5300` (avoid mDNS on 5353).

Bash / packaging scripts:
- Use `#!/usr/bin/env bash` and `set -euo pipefail`.
- Quote variables; use `install -Dm...` for file placement.
- Packaging scripts must not modify system DNS settings implicitly.
