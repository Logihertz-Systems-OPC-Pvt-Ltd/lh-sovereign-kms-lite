# Contributing to Logihertz Sovereign KMS Lite (`lh-kms`)

Thank you for your interest in contributing to **`lh-sovereign-kms-lite`** (`lh-kms`), an essential component of the Logihertz 60-Tool Sovereign Open-Source Ecosystem.

---

## 1. Zero External Dependency Mandate

`lh-sovereign-kms-lite` is engineered for air-gapped sovereign infrastructure, sensitive hardware security modules (HSMs), and high-assurance enclave deployments. To preserve complete audibility and eliminate supply-chain vulnerabilities:

- **100% Zero External Go Modules**: `go.mod` MUST contain zero `require` blocks.
- **Go Standard Library Exclusively**: All functionality must rely exclusively on packages provided by the official Go runtime (`crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/rand`, `crypto/sha256`, `crypto/subtle`, `encoding/hex`, `encoding/json`, `fmt`, `os`, `sort`, `strings`, `sync`, `time`, etc.).
- Pull requests introducing third-party modules or external packages will be rejected.

---

## 2. Mathematical & Cryptographic Rigor

When contributing to the core cryptographic primitives in `pkg/kms/`:

1. **Galois Field $GF(2^8)$ & Shamir Secret Sharing (`pkg/kms/shamir.go`)**:
   - Field arithmetic MUST utilize the irreducible primitive polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
   - Constant-time lookup tables (`gfExp`, `gfLog`) must be strictly bounded ($0 \le a < 256$).
   - Lagrange interpolation at $x=0$ must correctly compute basis coefficients $\ell_j(0) = \prod_{m \neq j} \left(x_m \otimes (x_j \oplus x_m)^{-1}\right)$.
   - Every share must be verified against its SHA-256 commitment using `crypto/subtle.ConstantTimeCompare`.

2. **AES-256-GCM Envelope Encryption (`pkg/kms/envelope.go`)**:
   - Master root key must remain zeroized until unsealed via threshold shares.
   - Key Encryption Keys (KEKs) must be derived using versioned HKDF/HMAC with distinct domain separators.
   - Canonical AAD serialization must sort map keys in deterministic lexicographical order (`k1=v1;k2=v2;...`).
   - Ephemeral Data Encryption Keys (DEKs) must be zeroized in RAM immediately after envelope sealing and unsealing.

3. **Posture Auditor (`pkg/kms/auditor.go`)**:
   - Deterministic rule IDs (`LH-KMS-001` through `LH-KMS-010`) must adhere to assigned CWE mappings and severities.
   - Posture scoring formula:
     $$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$

---

## 3. Development Workflow & Verification

Before submitting any code, verify that all static checks, formatters, and race-detection tests pass cleanly:

```bash
# 1. Format code according to Go standard specifications
gofmt -s -w .
test -z "$(gofmt -s -l .)"

# 2. Run static analysis
go vet ./...

# 3. Execute comprehensive test suite with race detector enabled
go test -v -race ./...

# 4. Build binary and verify CLI commands
go build -v -o bin/lh-kms ./cmd/lh-kms
./bin/lh-kms --version
./bin/lh-kms --help
./bin/lh-kms scan fixtures/hardened_kms_policy.json
./bin/lh-kms shamir-combine fixtures/sample_shamir_shares.json
./bin/lh-kms envelope-demo fixtures/sample_envelope_request.json
```

---

## 4. Git Commit Guidelines

- Format commit messages using conventional commits:
  - `feat(shamir): add verifiable share commitment check`
  - `fix(envelope): zeroize transient DEK on decrypt error`
  - `test(auditor): add edge case for mTLS requirement`
- All commits must be signed and attributed to legitimate contributors.
