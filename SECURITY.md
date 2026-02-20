# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in btlightning, **do not open a public issue**.

Instead, please email **security@inferencelabs.com** with:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- The impact and any affected versions you have identified

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 5 business days. Critical vulnerabilities affecting authentication or transport security will be prioritized for immediate patching.

## Scope

The following components are in scope for security reports:

| Component | Priority |
|-----------|----------|
| QUIC transport handshake (sr25519 signature verification) | Critical |
| Validator permit checking and cache management | High |
| Rate limiting and connection management | High |
| MessagePack serialization/deserialization | Medium |
| Python bindings (btlightning-py) | Medium |

## Known Transitive Advisories

The following RustSec advisories affect transitive dependencies and cannot be resolved without upstream major version bumps. They are documented in `.cargo/audit.toml` and `deny.toml` with impact assessments:

- **RUSTSEC-2024-0344** (curve25519-dalek) — timing variability via sp-core 21.0
- **RUSTSEC-2025-0009** (ring) — AES panic via quinn 0.10, release builds unaffected
- **RUSTSEC-2025-0055** (tracing-subscriber) — ANSI escape injection via sp-core 21.0
- **RUSTSEC-2023-0091, RUSTSEC-2024-0438, RUSTSEC-2025-0118** (wasmtime) — unused transitive dependency via sp-core 21.0
