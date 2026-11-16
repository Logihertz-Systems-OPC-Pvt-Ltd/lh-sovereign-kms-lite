# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-060`  
**Repository**: `lh-sovereign-kms-lite`  
**CLI Executable**: `lh-kms`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-060` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-sovereign-kms-lite` (`lh-kms`) |
| **Target Language / Platform** | `Go` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-kms` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `Go`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: GF(2^8) Shamir Lagrange Basis Interpolation at x = 0

The underlying computational core of `lh-sovereign-kms-lite` is formally governed by the following mathematical and algorithmic formulations:

$$\ell_j(0) = \prod_{m \neq j} \left(x_m \otimes (x_j \oplus x_m)^{-1}\right), \quad S[b] = \bigoplus_{j=0}^{M-1} y_{j,b} \otimes \ell_j(0)$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-KMS-001` | `CRITICAL` | `25` | `CWE-321` | -25 | Shamir Quorum Mandatory: Root key must not be auto-unsealed from plaintext files/env; requires Shamir $(M, N)$ threshold with $M \ge 2, N \ge 3$. |
| `LH-KMS-002` | `CRITICAL` | `25` | `CWE-327` | -25 | AEAD Cipher Enforcement: Mandates AES-256-GCM or ChaCha20-Poly1305 with 256-bit key length for all envelope operations. |
| `LH-KMS-003` | `CRITICAL` | `25` | `CWE-306` | -25 | Mutual TLS (mTLS) Client Verification: KMS API network interface must verify client certificates and disallow unauthenticated RPCs. |
| `LH-KMS-004` | `HIGH` | `10` | `CWE-345` | -10 | Mandatory Encryption Context (AAD): Requires deterministic canonical AAD context binding on all envelope operations to prevent confused-deputy attacks. |
| `LH-KMS-005` | `HIGH` | `10` | `CWE-324` | -10 | Automated KEK Version Rotation: Key Encryption Keys must automatically rotate with an interval $\le 90$ days. |
| `LH-KMS-006` | `HIGH` | `10` | `CWE-226` | -10 | Memory Locking & Zeroization: Root keys and transient DEKs must be locked in RAM (mlock), zeroized immediately after each operation, and OS swap disabled. |
| `LH-KMS-007` | `HIGH` | `10` | `CWE-330` | -10 | CSPRNG Health & GCM Invocation Limits: Continuous startup entropy verification and limit of $\le 10^8$ AES-GCM invocations per KEK version. |
| `LH-KMS-008` | `MEDIUM` | `4` | `CWE-285` | -4 | Raw Key Export Prohibition: Forbids raw KEK exports and enforces granular least-privilege RBAC for Encrypt, Decrypt, and Rewrap operations. |
| `LH-KMS-009` | `MEDIUM` | `4` | `CWE-400` | -4 | Deletion Safety Window & Tamper Auto-Seal: Mandates $\ge 7$ days pending-deletion waiting period and automated vault seal upon physical/intrusion alarms. |
| `LH-KMS-010` | `LOW` | `1` | `CWE-778` | -1 | Hash-Chained Audit Logging: Cryptographic unseal, rotation, and cryptographic events must be recorded to a tamper-evident SHA-256 hash-chain. |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-kms` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-kms <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-KMS-001` .. `LH-KMS-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-sovereign-kms-lite` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-sovereign-kms-lite`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-sovereign-kms-lite` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Add Feldman's Verifiable Secret Sharing (VSS) commitment verification during Shamir unseal and ChaCha20-Poly1305 / RFC 3394 AES-256-KW key wrapping. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement asymmetric envelope keys (Ed25519 signing, X25519 ECDH key agreement, RSA-OAEP-SHA256) and scoped per-tenant RBAC capability policies. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Add KMIP v2.1 (Key Management Interoperability Protocol) JSON/TTLV request-response compatibility and time-bounded lease tokens. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Implement encrypted persistent key-ring storage with automated background envelope re-wrapping and tamper-evident hash-chained audit logs. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Add Feldman's Verifiable Secret Sharing (VSS) commitment verification during Shamir unseal and ChaCha20-Poly1305 / RFC 3394 AES-256-KW key wrapping.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement asymmetric envelope keys (Ed25519 signing, X25519 ECDH key agreement, RSA-OAEP-SHA256) and scoped per-tenant RBAC capability policies.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Add KMIP v2.1 (Key Management Interoperability Protocol) JSON/TTLV request-response compatibility and time-bounded lease tokens.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Implement encrypted persistent key-ring storage with automated background envelope re-wrapping and tamper-evident hash-chained audit logs.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
