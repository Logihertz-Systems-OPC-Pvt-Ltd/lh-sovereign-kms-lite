# Logihertz Sovereign KMS Lite (`lh-kms`)

[![CI Pipeline](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-0%20External-brightgreen.svg)](go.mod)
[![Language: Go 1.22+](https://img.shields.io/badge/Language-Go%201.22+-00ADD8.svg)](go.mod)

**`lh-sovereign-kms-lite`** (`lh-kms`) is Repository #60 of the Logihertz 60-Tool Sovereign Open-Source Ecosystem — a production-grade, zero-dependency **Go On-Premise Envelope Key Management Service (KMS), Galois Field $GF(2^8)$ Shamir $(M, N)$ Threshold Secret Sharing Unseal Engine, NIST SP 800-38D AES-256-GCM Authenticated Envelope Encryptor, Versioned Key Rotator, and 10-Rule Sovereign KMS Posture Auditor**.

---

## Key Highlights

- **100% Zero External Dependencies (`go.mod` has zero `require` blocks)**: Implemented strictly using the Go Standard Library (`crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/rand`, `crypto/sha256`, `crypto/subtle`, `encoding/hex`, `encoding/json`, `sync`, etc.).
- **Galois Field $GF(2^8)$ Shamir $(M, N)$ Unseal Engine**: Reconstructs the 256-bit master root key from any $M$-of-$N$ threshold quorum using Lagrange interpolation at $x=0$, verified with constant-time SHA-256 commitments.
- **Three-Tier Sovereign Key Hierarchy**:
  - **Tier 1 (Master Root Key)**: Never saved to disk in plaintext. Vault starts in a `SEALED` state and reconstructs the root key only in memory upon receiving a valid Shamir quorum. Instant zeroization on `Seal()`.
  - **Tier 2 (Key Encryption Keys - KEKs)**: Versioned 256-bit keys derived per Key Ring (`KeyID`) using `HMAC-SHA256(MasterKey, "LH_KMS_KEK_V1:" || KeyID || ":v" || version)`.
  - **Tier 3 (Data Encryption Keys - DEKs)**: Fresh 256-bit ephemeral keys generated per envelope, used to encrypt bulk data payloads, and immediately zeroized in RAM.
- **NIST SP 800-38D AES-256-GCM Authenticated Envelope Encryption**: Binds all envelope wrapping and bulk payloads to canonical Additional Authenticated Data (`AAD`) formed from lexicographically sorted `EncryptionContext` pairs (`k1=v1;k2=v2;...`), preventing confused-deputy attacks.
- **Zero-Exposure Key Version Rotation & Envelope Re-Wrapping**: Key rotation increments the active KEK version ($v \to v+1$); `RewrapEnvelope` unwraps the historical DEK and re-wraps it under the new KEK version **without re-encrypting the bulk data ciphertext**.
- **10-Rule Normative Posture Auditor**: Audits KMS policies against MITRE CWE security checks (`LH-KMS-001` through `010`) and exports to ANSI Terminal Tables, Canonical JSON, and OASIS SARIF v2.1.0.

---

## Architectural Overview

```
                      SOVEREIGN ENCLAVE KMS LIFECYCLE & HIERARCHY
  +-----------------------------------------------------------------------------------------+
  |                                                                                         |
  |  +--------------------+        +---------------------+        +----------------------+  |
  |  |  Shamir Share #1   |        |   Shamir Share #2   |        |   Shamir Share #3    |  |
  |  | (x=1, y_1, Commit) |        | (x=3, y_3, Commit)  |        | (x=5, y_5, Commit)   |  |
  |  +--------------------+        +---------------------+        +----------------------+  |
  |            \                              |                              /              |
  |             \                             v                             /               |
  |              +---------------------------------------------------------+                |
  |              | GF(2^8) Lagrange Interpolation at x=0 (Primitive 0x11D) |                |
  |              |        Constant-Time SHA-256 Commitment Verification     |                |
  |              +---------------------------------------------------------+                |
  |                                           |                                             |
  |                                           v                                             |
  |                        +-------------------------------------+                          |
  |                        | TIER 1: MasterKey (256-bit in RAM)  | (Sealed -> Unsealed)     |
  |                        | Memory Zeroization via Seal()       |                          |
  |                        +-------------------------------------+                          |
  |                                           |                                             |
  |                                           v                                             |
  |              +---------------------------------------------------------+                |
  |              | TIER 2: HMAC-SHA256 KEK Derivation ("LH_KMS_KEK_V1:...")|                |
  |              | Versioned Key Rings: KEK(KeyID, v1), KEK(KeyID, v2)...  |                |
  |              +---------------------------------------------------------+                |
  |                                           |                                             |
  |                     +---------------------+---------------------+                       |
  |                     |                                           |                       |
  |                     v                                           v                       |
  |        +-------------------------+                 +-------------------------+          |
  |        | KEK-Wrapped DEK         |                 | AES-256-GCM Ciphertext  |          |
  |        | AES-256-GCM.Seal(KEK,   |                 | AES-256-GCM.Seal(DEK,   |          |
  |        |   Nonce_DEK, DEK, AAD)  |                 |   Nonce_PL, Plain, AAD) |          |
  |        +-------------------------+                 +-------------------------+          |
  |                     \                                           /                       |
  |                      \                                         /                        |
  |                       +---------------------------------------+                         |
  |                       | Canonical AAD: KeyID + Version + Map  |                         |
  |                       | "k1=v1;k2=v2;..." (Confused-Deputy    |                         |
  |                       |  Immunity)                            |                         |
  |                       +---------------------------------------+                         |
  |                                                                                         |
  +-----------------------------------------------------------------------------------------+
```

---

## Mathematical Foundations

### 1. Galois Field $GF(2^8)$ Arithmetic

All secret sharing arithmetic is performed over $GF(2^8)$ defined by the irreducible primitive polynomial:
$$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\texttt{0x11D})$$

With generator element $\alpha = 2$, precomputed logarithm (`gfLog`) and exponent (`gfExp`) tables enable constant-time branchless multiplication, division, and inversion:

$$\text{Mul}(a, b) = \begin{cases} 0 & \text{if } a=0 \lor b=0 \\ \text{exp}[(\text{log}[a] + \text{log}[b]) \bmod 255] & \text{otherwise} \end{cases}$$

$$\text{Inv}(a) = \text{exp}[255 - \text{log}[a]] \quad (\text{for } a \neq 0)$$

### 2. Shamir $(M, N)$ Polynomial Splitting & Lagrange Interpolation

To split an arbitrary 256-bit secret $S \in GF(2^8)^{32}$ into $N$ shares with threshold $M$:
1. For each byte position $b \in [0, 31]$, draw $M-1$ coefficients $a_1, \dots, a_{M-1} \xleftarrow{\$} \text{CSPRNG}$.
2. Evaluate degree-$(M-1)$ polynomial at coordinate $x_i = i \in \{1, \dots, N\}$ using Horner's method:
   $$y_{i, b} = f_b(x_i) = S[b] \oplus \bigoplus_{k=1}^{M-1} a_k \cdot x_i^k$$
3. To reconstruct $S$ from any $M$ distinct shares $\{(x_0, \mathbf{y}_0), \dots, (x_{M-1}, \mathbf{y}_{M-1})\}$, evaluate Lagrange interpolation at $x = 0$:
   $$\ell_j(0) = \prod_{\substack{m=0 \\ m \neq j}}^{M-1} \frac{0 - x_m}{x_j - x_m} = \prod_{\substack{m=0 \\ m \neq j}}^{M-1} \left( x_m \otimes (x_j \oplus x_m)^{-1} \right)$$
   $$S[b] = \bigoplus_{j=0}^{M-1} y_{j, b} \otimes \ell_j(0)$$

### 3. Canonical Additional Authenticated Data (`AAD`)

Every envelope encryption and decryption binds to the exact contextual authorization domain:
$$\text{AAD} = \texttt{"LH\_KMS\_ENV\_V1:key\_id="} \parallel \text{KeyID} \parallel \texttt{";version="} \parallel v \parallel \texttt{";context="} \parallel \text{LexicographicalSort}(\text{context})$$

---

## 10-Rule Sovereign KMS Security Posture Framework

The auditor evaluates policies against 10 deterministic security rules and computes the Logihertz Security Posture Score:
$$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$

| Rule ID | Severity | CWE | Deduction | Policy Check & Requirements |
| :--- | :--- | :---: | :---: | :--- |
| `LH-KMS-001` | **CRITICAL** | `CWE-321` | -25 | **Shamir Quorum Mandatory**: Root key must not be auto-unsealed from plaintext files/env; requires Shamir $(M, N)$ threshold with $M \ge 2, N \ge 3$. |
| `LH-KMS-002` | **CRITICAL** | `CWE-327` | -25 | **AEAD Cipher Enforcement**: Mandates AES-256-GCM or ChaCha20-Poly1305 with 256-bit key length for all envelope operations. |
| `LH-KMS-003` | **CRITICAL** | `CWE-306` | -25 | **Mutual TLS (mTLS) Client Verification**: KMS API network interface must verify client certificates and disallow unauthenticated RPCs. |
| `LH-KMS-004` | **HIGH** | `CWE-345` | -10 | **Mandatory Encryption Context (`AAD`)**: Requires deterministic canonical AAD context binding on all envelope operations to prevent confused-deputy attacks. |
| `LH-KMS-005` | **HIGH** | `CWE-324` | -10 | **Automated KEK Version Rotation**: Key Encryption Keys must automatically rotate with an interval $\le 90$ days. |
| `LH-KMS-006` | **HIGH** | `CWE-226` | -10 | **Memory Locking & Zeroization**: Root keys and transient DEKs must be locked in RAM (`mlock`), zeroized immediately after each operation, and OS swap disabled. |
| `LH-KMS-007` | **HIGH** | `CWE-330` | -10 | **CSPRNG Health & GCM Invocation Limits**: Continuous startup entropy verification and limit of $\le 10^8$ AES-GCM invocations per KEK version. |
| `LH-KMS-008` | **MEDIUM** | `CWE-285` | -4 | **Raw Key Export Prohibition**: Forbids raw KEK exports and enforces granular least-privilege RBAC for Encrypt, Decrypt, and Rewrap operations. |
| `LH-KMS-009` | **MEDIUM** | `CWE-400` | -4 | **Deletion Safety Window & Tamper Auto-Seal**: Mandates $\ge 7$ days pending-deletion waiting period and automated vault seal upon physical/intrusion alarms. |
| `LH-KMS-010` | **LOW** | `CWE-778` | -1 | **Hash-Chained Audit Logging**: Cryptographic unseal, rotation, and cryptographic events must be recorded to a tamper-evident SHA-256 hash-chain. |

---

## CLI Usage Guide

### 1. Build Binary
```bash
go build -v -o bin/lh-kms ./cmd/lh-kms
```

### 2. Audit a KMS Policy Manifest
```bash
# Scan policy and output ANSI box-drawing report
./bin/lh-kms scan fixtures/hardened_kms_policy.json

# Export Canonical JSON
./bin/lh-kms scan fixtures/hardened_kms_policy.json --format json

# Export OASIS SARIF v2.1.0 for CI/CD ingestion
./bin/lh-kms scan fixtures/hardened_kms_policy.json --format sarif --output report.sarif
```

### 3. Split a 256-bit Secret into Shamir Shares
```bash
./bin/lh-kms shamir-split \
  --secret-hex 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
  --threshold 3 \
  --shares 5 \
  --output my_shares.json
```

### 4. Reconstruct Secret from Shares
```bash
./bin/lh-kms shamir-combine fixtures/sample_shamir_shares.json
```

### 5. Execute Full Envelope Lifecycle Demo
```bash
./bin/lh-kms envelope-demo fixtures/sample_envelope_request.json
```

---

## Verification & Testing

```bash
# Verify Go formatting
gofmt -s -l .

# Run static analysis
go vet ./...

# Run test suite with race detector (85+ assertions)
go test -v -race ./...
```

---

## License & Attribution

Copyright 2026 Logihertz Systems (OPC) Private Limited.  
Creator, Founder, Director & Sole Developer: **Sameer Tawade** (`ops@logihertz.com` / `security@logihertz.com`).

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
