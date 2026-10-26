# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-26

### Added
- `dkim-checker` CLI with selector probing, `--json`, `--strict` and offline `--record` linting
- RFC 6376 key-record parser (v, k, p, h, t, s, n) with RSA and Ed25519 public key decoding
- Key strength lints: under 1024 bits, under 2048 bits, revoked keys, t=y testing mode, sha1-only
- Probing of 30+ selectors used by popular mail providers
- Library API (`checkDkim`, `parseDkim`, `lintDkim`) with injectable resolver, and GitHub Action

[1.0.0]: https://github.com/ksanyok/dkim-checker/releases/tag/v1.0.0
