# Changelog

All notable changes to **`lh-sovereign-kms-lite`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-16

### Added
- **Galois Field $GF(2^8)$ Shamir $(M, N)$ Threshold Secret Sharing**:
  - Pure-Go implementation of $GF(2^8)$ field arithmetic using irreducible polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
  - Polynomial secret splitting (`SplitSecret`) with random coefficients and 1-based non-zero coordinates.
  - Constant-time verifiable share commitment with domain-separated SHA-256 (`LH_SHAMIR_COMMIT:`).
  - Lagrange polynomial interpolation at $x=0$ (`CombineShares`) recovering the exact 256-bit root master key from any $M$-of-$N$ valid shares.
- **Three-Tier Sovereign Envelope Key Management Service (KMS)**:
  - Three-tier hierarchy: Ephemeral `MasterKey` (Tier 1), Versioned `KEK`s (Tier 2), and Ephemeral `DEK`s (Tier 3).
  - Sealed vault lifecycle with `UnsealWithShares` and instant memory zeroization via `Seal`.
  - NIST SP 800-38D compliant AES-256-GCM envelope encryption (`EncryptEnvelope` / `DecryptEnvelope`).
  - Deterministic Canonical Additional Authenticated Data (`AAD`) context binding (`k1=v1;k2=v2;...`).
  - Zero-exposure key version rotation (`RotateKeyVersion`) and envelope re-wrapping (`RewrapEnvelope`).
  - Memory zeroization primitives (`ZeroizeBytes`) for sensitive key slices.
- **10-Rule Sovereign KMS Posture Auditor**:
  - Deterministic evaluation of rules `LH-KMS-001` through `LH-KMS-010` mapping to MITRE CWEs.
  - Standardized Logihertz Security Posture Score calculation $S_{\text{posture}} \in [0, 100]$.
  - Multi-format exporters: ANSI Terminal Box Table, Canonical JSON, and OASIS SARIF v2.1.0.
- **`lh-kms` CLI Command Suite**:
  - Subcommands: `scan`, `shamir-split`, `shamir-combine`, `envelope-demo`, `--version`, and `--help`.
  - Standardized exit codes: `0` (Success / Valid), `1` (Policy Violation / Verification Failure), `2` (CLI Syntax / Execution Error).
- **Test Suite & Fixtures**:
  - 85+ unit, integration, and mathematical assertions in `pkg/kms/kms_test.go` with race detector support.
  - Comprehensive test fixtures: `hardened_kms_policy.json`, `vulnerable_kms_policy.json`, `sample_shamir_shares.json`, and `sample_envelope_request.json`.
  - GitHub Actions CI matrix with automated `gofmt`, `go vet`, and `go test -v -race` validation.
