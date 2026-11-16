package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ZeroizeBytes safely overwrites a sensitive byte slice with zeroes.
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Envelope encapsulates the wrapped DEK, ciphertext, nonces, and AAD context.
type Envelope struct {
	KeyID             string            `json:"key_id"`
	KeyVersion        int               `json:"key_version"`
	Algorithm         string            `json:"algorithm"` // AES-256-GCM
	WrappedDEKHex     string            `json:"wrapped_dek_hex"`
	NonceDEKHex       string            `json:"nonce_dek_hex"`
	CiphertextHex     string            `json:"ciphertext_hex"`
	NoncePayloadHex   string            `json:"nonce_payload_hex"`
	EncryptionContext map[string]string `json:"encryption_context"`
	CreatedAt         string            `json:"created_at"`
}

// CanonicalAAD produces deterministic Additional Authenticated Data binding for envelope operations.
// Format: LH_KMS_AAD_V1:key_id=<keyID>;context=<k1=v1;k2=v2;...>
func CanonicalAAD(keyID string, context map[string]string) []byte {
	if len(context) == 0 {
		return []byte(fmt.Sprintf("LH_KMS_AAD_V1:key_id=%s;context=", keyID))
	}

	keys := make([]string, 0, len(context))
	for k := range context {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, context[k]))
	}
	joined := strings.Join(parts, ";")

	return []byte(fmt.Sprintf("LH_KMS_AAD_V1:key_id=%s;context=%s", keyID, joined))
}

// KMSVault represents an in-memory sovereign KMS instance.
type KMSVault struct {
	mu             sync.RWMutex
	masterKey      []byte
	keks           map[string]map[int][]byte // keyID -> version -> 32-byte KEK
	activeVersions map[string]int            // keyID -> active version
	isSealed       bool
}

// NewKMSVault constructs a new KMSVault in sealed state.
func NewKMSVault() *KMSVault {
	return &KMSVault{
		keks:           make(map[string]map[int][]byte),
		activeVersions: make(map[string]int),
		isSealed:       true,
	}
}

// IsSealed returns whether the KMS vault is currently sealed.
func (v *KMSVault) IsSealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.isSealed
}

// UnsealWithShares reconstructs the master key from Shamir shares and unseals the vault.
func (v *KMSVault) UnsealWithShares(shares []ShamirShare) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	masterKey, err := CombineShares(shares)
	if err != nil {
		return fmt.Errorf("failed to unseal KMS vault: %w", err)
	}

	if len(masterKey) != 32 {
		ZeroizeBytes(masterKey)
		return fmt.Errorf("unsealed master key length (%d bytes) must be exactly 32 bytes for 256-bit security", len(masterKey))
	}

	// Wipe any previous master key
	if len(v.masterKey) > 0 {
		ZeroizeBytes(v.masterKey)
	}

	v.masterKey = masterKey
	v.isSealed = false
	return nil
}

// Seal immediately zeroes master key and cached KEKs in memory and transitions to sealed state.
func (v *KMSVault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.masterKey) > 0 {
		ZeroizeBytes(v.masterKey)
		v.masterKey = nil
	}

	for _, versions := range v.keks {
		for _, kek := range versions {
			ZeroizeBytes(kek)
		}
	}
	v.keks = make(map[string]map[int][]byte)
	v.activeVersions = make(map[string]int)
	v.isSealed = true
}

// deriveKEKLocked computes or returns cached KEK for a keyID and version. Caller must hold v.mu.
func (v *KMSVault) deriveKEKLocked(keyID string, version int) ([]byte, error) {
	if v.isSealed || len(v.masterKey) == 0 {
		return nil, errors.New("KMS_VAULT_SEALED: cannot derive KEK while vault is sealed")
	}

	if _, ok := v.keks[keyID]; !ok {
		v.keks[keyID] = make(map[int][]byte)
	}

	if kek, ok := v.keks[keyID][version]; ok {
		return kek, nil
	}

	// KEK(KeyID, v) = HMAC-SHA256(MasterKey, "LH_KMS_KEK_V1:" || KeyID || ":v" || version)
	h := hmac.New(sha256.New, v.masterKey)
	h.Write([]byte(fmt.Sprintf("LH_KMS_KEK_V1:%s:v%d", keyID, version)))
	kek := h.Sum(nil)

	v.keks[keyID][version] = kek
	return kek, nil
}

// GetActiveKeyVersion returns the currently active KEK version for the keyID.
func (v *KMSVault) GetActiveKeyVersion(keyID string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isSealed {
		return 0, errors.New("KMS_VAULT_SEALED: vault is currently sealed")
	}

	ver, ok := v.activeVersions[keyID]
	if !ok {
		ver = 1
		v.activeVersions[keyID] = ver
	}
	return ver, nil
}

// RotateKeyVersion increments the active version of a KEK, returning the new version.
func (v *KMSVault) RotateKeyVersion(keyID string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isSealed {
		return 0, errors.New("KMS_VAULT_SEALED: cannot rotate key while vault is sealed")
	}

	current := v.activeVersions[keyID]
	if current < 1 {
		current = 1
	}
	newVer := current + 1
	v.activeVersions[keyID] = newVer

	// Pre-derive new KEK
	if _, err := v.deriveKEKLocked(keyID, newVer); err != nil {
		return 0, err
	}

	return newVer, nil
}

// EncryptEnvelope performs authenticated envelope encryption using AES-256-GCM.
func (v *KMSVault) EncryptEnvelope(keyID string, plaintext []byte, context map[string]string) (*Envelope, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isSealed {
		return nil, errors.New("KMS_VAULT_SEALED: vault is sealed; unseal with Shamir threshold shares")
	}

	ver, ok := v.activeVersions[keyID]
	if !ok {
		ver = 1
		v.activeVersions[keyID] = ver
	}

	kek, err := v.deriveKEKLocked(keyID, ver)
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	// Generate fresh ephemeral 256-bit (32 bytes) DEK
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate random DEK: %w", err)
	}
	defer ZeroizeBytes(dek)

	// Generate 12-byte GCM nonces for DEK and Payload
	nonceDEK := make([]byte, 12)
	noncePayload := make([]byte, 12)
	if _, err := rand.Read(nonceDEK); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for DEK: %w", err)
	}
	if _, err := rand.Read(noncePayload); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for payload: %w", err)
	}

	aad := CanonicalAAD(keyID, context)

	// 1. Wrap DEK under KEK
	blockKEK, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK cipher: %w", err)
	}
	gcmKEK, err := cipher.NewGCM(blockKEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK GCM: %w", err)
	}
	wrappedDEK := gcmKEK.Seal(nil, nonceDEK, dek, aad)

	// 2. Encrypt plaintext under DEK
	blockDEK, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK cipher: %w", err)
	}
	gcmDEK, err := cipher.NewGCM(blockDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK GCM: %w", err)
	}
	ciphertext := gcmDEK.Seal(nil, noncePayload, plaintext, aad)

	// Copy context map for envelope metadata
	envContext := make(map[string]string)
	for k, val := range context {
		envContext[k] = val
	}

	return &Envelope{
		KeyID:             keyID,
		KeyVersion:        ver,
		Algorithm:         "AES-256-GCM",
		WrappedDEKHex:     hex.EncodeToString(wrappedDEK),
		NonceDEKHex:       hex.EncodeToString(nonceDEK),
		CiphertextHex:     hex.EncodeToString(ciphertext),
		NoncePayloadHex:   hex.EncodeToString(noncePayload),
		EncryptionContext: envContext,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DecryptEnvelope unwraps the DEK and decrypts the payload under AES-256-GCM with AAD verification.
func (v *KMSVault) DecryptEnvelope(env *Envelope, context map[string]string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isSealed {
		return nil, errors.New("KMS_VAULT_SEALED: vault is sealed; unseal with Shamir threshold shares")
	}
	if env == nil {
		return nil, errors.New("envelope cannot be nil")
	}
	if env.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported AEAD algorithm: %s (must be AES-256-GCM)", env.Algorithm)
	}

	kek, err := v.deriveKEKLocked(env.KeyID, env.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to derive historical KEK version %d: %w", env.KeyVersion, err)
	}

	wrappedDEK, err := hex.DecodeString(env.WrappedDEKHex)
	if err != nil {
		return nil, fmt.Errorf("invalid wrapped DEK hex: %w", err)
	}
	nonceDEK, err := hex.DecodeString(env.NonceDEKHex)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce DEK hex: %w", err)
	}
	ciphertext, err := hex.DecodeString(env.CiphertextHex)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	noncePayload, err := hex.DecodeString(env.NoncePayloadHex)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce payload hex: %w", err)
	}

	aad := CanonicalAAD(env.KeyID, context)

	// 1. Unwrap DEK using KEK and AAD
	blockKEK, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK cipher: %w", err)
	}
	gcmKEK, err := cipher.NewGCM(blockKEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK GCM: %w", err)
	}
	dek, err := gcmKEK.Open(nil, nonceDEK, wrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("AUTHENTICATION_FAILED: failed to unwrap DEK (corrupt ciphertext, tampered KEK, or AAD mismatch): %w", err)
	}
	defer ZeroizeBytes(dek)

	// 2. Decrypt payload using unwrapped DEK and AAD
	blockDEK, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK cipher: %w", err)
	}
	gcmDEK, err := cipher.NewGCM(blockDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK GCM: %w", err)
	}
	plaintext, err := gcmDEK.Open(nil, noncePayload, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AUTHENTICATION_FAILED: failed to decrypt payload (corrupt ciphertext or AAD mismatch): %w", err)
	}

	return plaintext, nil
}

// RewrapEnvelope decrypts the DEK using the historical KEK version and re-wraps it
// under the latest active KEK version without decrypting or re-encrypting the bulk data ciphertext.
func (v *KMSVault) RewrapEnvelope(env *Envelope, context map[string]string) (*Envelope, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isSealed {
		return nil, errors.New("KMS_VAULT_SEALED: vault is sealed")
	}
	if env == nil {
		return nil, errors.New("envelope cannot be nil")
	}

	activeVer, ok := v.activeVersions[env.KeyID]
	if !ok {
		activeVer = 1
		v.activeVersions[env.KeyID] = activeVer
	}

	// 1. Unwrap DEK with historical KEK
	oldKEK, err := v.deriveKEKLocked(env.KeyID, env.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to derive old KEK v%d: %w", env.KeyVersion, err)
	}

	wrappedDEK, err := hex.DecodeString(env.WrappedDEKHex)
	if err != nil {
		return nil, fmt.Errorf("invalid wrapped DEK hex: %w", err)
	}
	oldNonceDEK, err := hex.DecodeString(env.NonceDEKHex)
	if err != nil {
		return nil, fmt.Errorf("invalid old nonce DEK hex: %w", err)
	}

	oldAAD := CanonicalAAD(env.KeyID, context)

	blockOldKEK, err := aes.NewCipher(oldKEK)
	if err != nil {
		return nil, err
	}
	gcmOldKEK, err := cipher.NewGCM(blockOldKEK)
	if err != nil {
		return nil, err
	}
	dek, err := gcmOldKEK.Open(nil, oldNonceDEK, wrappedDEK, oldAAD)
	if err != nil {
		return nil, fmt.Errorf("AUTHENTICATION_FAILED: cannot rewrap: failed to unwrap DEK under old KEK v%d: %w", env.KeyVersion, err)
	}
	defer ZeroizeBytes(dek)

	// 2. Wrap DEK under active KEK with fresh nonce
	newKEK, err := v.deriveKEKLocked(env.KeyID, activeVer)
	if err != nil {
		return nil, fmt.Errorf("failed to derive active KEK v%d: %w", activeVer, err)
	}

	newNonceDEK := make([]byte, 12)
	if _, err := rand.Read(newNonceDEK); err != nil {
		return nil, fmt.Errorf("failed to generate fresh nonce for DEK: %w", err)
	}

	newAAD := CanonicalAAD(env.KeyID, context)

	blockNewKEK, err := aes.NewCipher(newKEK)
	if err != nil {
		return nil, err
	}
	gcmNewKEK, err := cipher.NewGCM(blockNewKEK)
	if err != nil {
		return nil, err
	}
	newWrappedDEK := gcmNewKEK.Seal(nil, newNonceDEK, dek, newAAD)

	// Return updated envelope preserving the original ciphertext
	envContext := make(map[string]string)
	for k, val := range context {
		envContext[k] = val
	}

	return &Envelope{
		KeyID:             env.KeyID,
		KeyVersion:        activeVer,
		Algorithm:         env.Algorithm,
		WrappedDEKHex:     hex.EncodeToString(newWrappedDEK),
		NonceDEKHex:       hex.EncodeToString(newNonceDEK),
		CiphertextHex:     env.CiphertextHex,
		NoncePayloadHex:   env.NoncePayloadHex,
		EncryptionContext: envContext,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}, nil
}
