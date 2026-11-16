# Security Policy

## Supported Versions

Logihertz Systems (OPC) Private Limited actively maintains and provides security patches for the following versions of `lh-sovereign-kms-lite`:

| Version | Supported          | Release Date | Maintenance Status |
| ------- | ------------------ | ------------ | ------------------ |
| 0.1.x   | :white_check_mark: | 2026-11-16   | Current Stable     |

---

## Security Architecture & Threat Model

`lh-sovereign-kms-lite` (`lh-kms`) is an air-gapped, sovereign, on-premise Key Management Service engineered for mission-critical enclaves, edge clusters, and private data centers. The implementation relies on strict cryptographic principles:

1. **Three-Tier Key Hierarchy**:
   - **Tier 1: Master Root Key (`MasterKey`, 256 bits)**: Never persisted to disk in plaintext. The vault boots in a strictly `SEALED` state. The root key is reconstructed ephemerally into locked RAM only when a valid quorum of Shamir shares is submitted (`UnsealWithShares`).
   - **Tier 2: Key Encryption Keys (`KEK`, 256 bits)**: Derived per Key Ring (`KeyID`) and integer version $v \ge 1$ via `HMAC-SHA256(MasterKey, "LH_KMS_KEK_V1:" || KeyID || ":v" || v)`.
   - **Tier 3: Data Encryption Keys (`DEK`, 256 bits)**: Generated ephemerally per envelope using CSPRNG (`crypto/rand`), used immediately to encrypt application payloads, and zeroized in RAM immediately thereafter (`ZeroizeBytes`).

2. **Galois Field $GF(2^8)$ Shamir $(M, N)$ Threshold Secret Sharing**:
   - Built over irreducible primitive polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
   - Lagrange interpolation at $x=0$ reconstructs the root key if and only if $M$ distinct, authentic shares are presented.
   - Every share is cryptographically committed using constant-time verified SHA-256 commitments to detect tampered or forged shares prior to key material derivation.

3. **NIST SP 800-38D AES-256-GCM Envelope Encryption & Canonical AAD**:
   - All wrapping of DEKs and encryption of payloads enforce 256-bit AES-GCM authenticated encryption.
   - Mandatory Additional Authenticated Data (`AAD`) binds the ciphertext to the exact KeyID, Key Version, and canonical lexicographically-sorted `EncryptionContext` (`k1=v1;k2=v2;...`), preventing confused-deputy and ciphertext relocation attacks across enclaves.

4. **Zero-Exposure Key Version Rotation & Memory Zeroization**:
   - Key rotation generates a new versioned KEK without re-encrypting existing bulk data payloads; the `RewrapEnvelope` operation decrypts and re-wraps only the wrapped DEK under the latest KEK version.
   - All transient slices holding root keys, KEKs, and DEKs are zeroized in RAM immediately upon completion of the cryptographic operation or upon invoking `Seal()`.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in `lh-sovereign-kms-lite`, please adhere to responsible disclosure guidelines:

- **Primary Security Contact**: Sameer Tawade (`security@logihertz.com`)
- **Operations Contact**: `ops@logihertz.com`
- **PGP Encryption**: Security reports may be encrypted with our designated security team public key.
- **Response Timeline**:
  - Initial acknowledgment: Within 24 hours.
  - Vulnerability assessment & reproduction: Within 72 hours.
  - Security advisory & patch release: Within 7 calendar days.

Please provide:
- Comprehensive description of the potential vulnerability.
- Steps to reproduce, including minimal test vectors or sample policies.
- Affected components (Shamir engine, envelope wrapper, auditor, or CLI).
- Potential impact and threat vector evaluation.

We kindly request that you refrain from public disclosure until a security advisory and remediation patch have been released.
