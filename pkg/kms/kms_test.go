package kms_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite/pkg/kms"
)

// =========================================================================
// 1. Galois Field GF(2^8) Arithmetic Tests
// =========================================================================

func TestGF256FieldAxioms(t *testing.T) {
	// Identity and Zero
	for a := 0; a < 256; a++ {
		ba := byte(a)
		if got := kms.GF256Mul(ba, 1); got != ba {
			t.Fatalf("GF256Mul(%d, 1) = %d; want %d", a, got, a)
		}
		if got := kms.GF256Mul(ba, 0); got != 0 {
			t.Fatalf("GF256Mul(%d, 0) = %d; want 0", a, got)
		}
	}

	// Commutativity: a * b == b * a
	for a := 1; a < 30; a++ {
		for b := 1; b < 30; b++ {
			p1 := kms.GF256Mul(byte(a), byte(b))
			p2 := kms.GF256Mul(byte(b), byte(a))
			if p1 != p2 {
				t.Fatalf("Commutativity failed: %d * %d = %d != %d", a, b, p1, p2)
			}
		}
	}

	// Associativity: (a * b) * c == a * (b * c)
	for a := 1; a < 15; a++ {
		for b := 1; b < 15; b++ {
			for c := 1; c < 15; c++ {
				lhs := kms.GF256Mul(kms.GF256Mul(byte(a), byte(b)), byte(c))
				rhs := kms.GF256Mul(byte(a), kms.GF256Mul(byte(b), byte(c)))
				if lhs != rhs {
					t.Fatalf("Associativity failed: (%d * %d) * %d = %d != %d", a, b, c, lhs, rhs)
				}
			}
		}
	}

	// Multiplicative Inverses: for all a in [1, 255], a * a^-1 == 1
	for a := 1; a < 256; a++ {
		ba := byte(a)
		inv, err := kms.GF256Inv(ba)
		if err != nil {
			t.Fatalf("GF256Inv(%d) unexpected error: %v", a, err)
		}
		prod := kms.GF256Mul(ba, inv)
		if prod != 1 {
			t.Fatalf("GF256Inv(%d) = %d, product = %d; want 1", a, inv, prod)
		}
	}

	// Inverse of 0 must fail
	if _, err := kms.GF256Inv(0); err == nil {
		t.Fatal("GF256Inv(0) should return error")
	}

	// Division: (a * b) / b == a for all b != 0
	for a := 0; a < 50; a++ {
		for b := 1; b < 50; b++ {
			ba := byte(a)
			bb := byte(b)
			prod := kms.GF256Mul(ba, bb)
			quot, err := kms.GF256Div(prod, bb)
			if err != nil {
				t.Fatalf("GF256Div unexpected error: %v", err)
			}
			if quot != ba {
				t.Fatalf("GF256Div(%d * %d / %d) = %d; want %d", a, b, b, quot, a)
			}
		}
	}

	// Division by 0 must fail
	if _, err := kms.GF256Div(10, 0); err == nil {
		t.Fatal("GF256Div by zero should return error")
	}
}

// =========================================================================
// 2. Shamir (M, N) Threshold Secret Sharing Tests
// =========================================================================

func TestShamirSecretSplitValidation(t *testing.T) {
	// Empty secret
	if _, err := kms.SplitSecret(nil, 3, 5); err == nil {
		t.Fatal("SplitSecret with nil secret should return error")
	}

	// Threshold < 2
	if _, err := kms.SplitSecret([]byte("test"), 1, 5); err == nil {
		t.Fatal("SplitSecret with threshold 1 should return error")
	}

	// Total shares < threshold
	if _, err := kms.SplitSecret([]byte("test"), 4, 3); err == nil {
		t.Fatal("SplitSecret with total < threshold should return error")
	}

	// Total shares > 255
	if _, err := kms.SplitSecret([]byte("test"), 3, 256); err == nil {
		t.Fatal("SplitSecret with total > 255 should return error")
	}
}

func TestShamirSecretSplitAndCombineRoundtrip(t *testing.T) {
	// 256-bit (32 bytes) secret
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	shares, err := kms.SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Subsets of size 3 (any 3-of-5)
	subsets := [][]int{
		{0, 1, 2}, // {1, 2, 3}
		{0, 2, 4}, // {1, 3, 5}
		{1, 3, 4}, // {2, 4, 5}
		{2, 3, 4}, // {3, 4, 5}
		{4, 2, 0}, // reversed order {5, 3, 1}
	}

	for _, sub := range subsets {
		chosen := []kms.ShamirShare{shares[sub[0]], shares[sub[1]], shares[sub[2]]}
		reconstructed, err := kms.CombineShares(chosen)
		if err != nil {
			t.Fatalf("CombineShares failed for subset %v: %v", sub, err)
		}
		if !bytes.Equal(reconstructed, secret) {
			t.Fatalf("reconstructed secret mismatch for subset %v:\ngot:  %x\nwant: %x", sub, reconstructed, secret)
		}
	}

	// Providing all 5 shares also recovers the secret
	allReconstructed, err := kms.CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares with all shares failed: %v", err)
	}
	if !bytes.Equal(allReconstructed, secret) {
		t.Fatal("all shares reconstruction mismatch")
	}
}

func TestShamirInsufficientShares(t *testing.T) {
	secret := []byte("LOGIHERTZ_AIRGAP_KMS_SECRET_256!")
	shares, err := kms.SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Provide only 2 shares when 3 are required
	_, err = kms.CombineShares(shares[:2])
	if err == nil || !strings.Contains(err.Error(), "INSUFFICIENT_SHAMIR_SHARES") {
		t.Fatalf("expected INSUFFICIENT_SHAMIR_SHARES error, got: %v", err)
	}
}

func TestShamirDuplicateShareIndices(t *testing.T) {
	secret := []byte("LOGIHERTZ_AIRGAP_KMS_SECRET_256!")
	shares, err := kms.SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Duplicate index: {1, 1, 2}
	dups := []kms.ShamirShare{shares[0], shares[0], shares[1]}
	_, err = kms.CombineShares(dups)
	if err == nil || !strings.Contains(err.Error(), "INSUFFICIENT_SHAMIR_SHARES") {
		t.Fatalf("expected INSUFFICIENT_SHAMIR_SHARES for duplicate shares, got: %v", err)
	}
}

func TestShamirTamperedShareRejection(t *testing.T) {
	secret := []byte("LOGIHERTZ_AIRGAP_KMS_SECRET_256!")
	shares, err := kms.SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Tamper with 1 byte in share 1
	tampered := make([]kms.ShamirShare, 3)
	copy(tampered, shares[:3])

	raw, _ := hex.DecodeString(tampered[0].ShareBytesHex)
	raw[0] ^= 0x01 // flip 1 bit
	tampered[0].ShareBytesHex = hex.EncodeToString(raw)

	_, err = kms.CombineShares(tampered)
	if err == nil || !strings.Contains(err.Error(), "SHAMIR_COMMITMENT_MISMATCH") {
		t.Fatalf("expected SHAMIR_COMMITMENT_MISMATCH error, got: %v", err)
	}
}

func TestShamirSampleFixtureDeterministic(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/sample_shamir_shares.json")
	if err != nil {
		t.Fatalf("failed to read sample_shamir_shares.json: %v", err)
	}

	var manifest kms.ShamirShareManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("failed to parse sample_shamir_shares.json: %v", err)
	}

	reconstructed, err := kms.CombineShares(manifest.Shares)
	if err != nil {
		t.Fatalf("failed to combine sample shares: %v", err)
	}

	// Expected secret is bytes [1..32]
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = byte(i + 1)
	}

	if !bytes.Equal(reconstructed, expected) {
		t.Fatalf("fixture reconstruction mismatch:\ngot:  %x\nwant: %x", reconstructed, expected)
	}
}

// =========================================================================
// 3. AES-256-GCM Envelope Encryption, AAD Context & Rotation Tests
// =========================================================================

func TestKMSVaultLifecycleAndSeal(t *testing.T) {
	vault := kms.NewKMSVault()
	if !vault.IsSealed() {
		t.Fatal("new vault must be in sealed state")
	}

	context := map[string]string{"env": "prod"}
	_, err := vault.EncryptEnvelope("key-1", []byte("secret"), context)
	if err == nil || !strings.Contains(err.Error(), "KMS_VAULT_SEALED") {
		t.Fatalf("expected KMS_VAULT_SEALED on encrypt, got: %v", err)
	}

	_, err = vault.DecryptEnvelope(&kms.Envelope{Algorithm: "AES-256-GCM"}, context)
	if err == nil || !strings.Contains(err.Error(), "KMS_VAULT_SEALED") {
		t.Fatalf("expected KMS_VAULT_SEALED on decrypt, got: %v", err)
	}

	_, err = vault.RotateKeyVersion("key-1")
	if err == nil || !strings.Contains(err.Error(), "KMS_VAULT_SEALED") {
		t.Fatalf("expected KMS_VAULT_SEALED on rotate, got: %v", err)
	}

	_, err = vault.RewrapEnvelope(&kms.Envelope{}, context)
	if err == nil || !strings.Contains(err.Error(), "KMS_VAULT_SEALED") {
		t.Fatalf("expected KMS_VAULT_SEALED on rewrap, got: %v", err)
	}

	// Unseal vault
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 0x42)
	}
	shares, err := kms.SplitSecret(masterKey, 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	if err := vault.UnsealWithShares(shares[:2]); err != nil {
		t.Fatalf("UnsealWithShares failed: %v", err)
	}
	if vault.IsSealed() {
		t.Fatal("vault should not be sealed after UnsealWithShares")
	}

	// Seal vault again
	vault.Seal()
	if !vault.IsSealed() {
		t.Fatal("vault must be sealed after Seal()")
	}

	// Post-seal operation must fail
	_, err = vault.EncryptEnvelope("key-1", []byte("secret"), context)
	if err == nil || !strings.Contains(err.Error(), "KMS_VAULT_SEALED") {
		t.Fatalf("expected KMS_VAULT_SEALED after seal, got: %v", err)
	}
}

func TestEnvelopeEncryptDecryptRoundtrip(t *testing.T) {
	vault := kms.NewKMSVault()
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	shares, _ := kms.SplitSecret(masterKey, 2, 3)
	vault.UnsealWithShares(shares[:2])

	plaintext := []byte("LOGIHERTZ_SOVEREIGN_ENVELOPE_PLAIN_TEXT_TEST_12345")
	context := map[string]string{
		"enclave": "mumbai-edge-01",
		"service": "luks-driver",
		"tenant":  "ops-infra",
	}

	env, err := vault.EncryptEnvelope("root-keyring-01", plaintext, context)
	if err != nil {
		t.Fatalf("EncryptEnvelope failed: %v", err)
	}
	if env.KeyVersion != 1 {
		t.Fatalf("expected key version 1, got %d", env.KeyVersion)
	}
	if env.Algorithm != "AES-256-GCM" {
		t.Fatalf("expected AES-256-GCM algorithm, got %s", env.Algorithm)
	}

	// Decrypt with identical context
	decrypted, err := vault.DecryptEnvelope(env, context)
	if err != nil {
		t.Fatalf("DecryptEnvelope failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\ngot:  %s\nwant: %s", string(decrypted), string(plaintext))
	}
}

func TestCanonicalAADOrderIndependence(t *testing.T) {
	ctx1 := map[string]string{"b": "2", "a": "1", "c": "3"}
	ctx2 := map[string]string{"a": "1", "c": "3", "b": "2"}

	aad1 := kms.CanonicalAAD("key-1", ctx1)
	aad2 := kms.CanonicalAAD("key-1", ctx2)

	if !bytes.Equal(aad1, aad2) {
		t.Fatalf("canonical AAD mismatch for reordered maps:\n%s\nvs\n%s", string(aad1), string(aad2))
	}

	expected := "LH_KMS_AAD_V1:key_id=key-1;context=a=1;b=2;c=3"
	if string(aad1) != expected {
		t.Fatalf("unexpected canonical AAD format:\ngot:  %s\nwant: %s", string(aad1), expected)
	}
}

func TestEnvelopeTamperRejections(t *testing.T) {
	vault := kms.NewKMSVault()
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	shares, _ := kms.SplitSecret(masterKey, 2, 3)
	vault.UnsealWithShares(shares[:2])

	plaintext := []byte("HIGH_INTEGRITY_KMS_PAYLOAD")
	context := map[string]string{"tenant": "finance", "cluster": "alpha"}

	env, err := vault.EncryptEnvelope("tamper-test-key", plaintext, context)
	if err != nil {
		t.Fatalf("EncryptEnvelope failed: %v", err)
	}

	// 1. Context AAD mismatch: changed tenant
	badContext := map[string]string{"tenant": "engineering", "cluster": "alpha"}
	_, err = vault.DecryptEnvelope(env, badContext)
	if err == nil || !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("expected AUTHENTICATION_FAILED on AAD mismatch, got: %v", err)
	}

	// 2. Tampered wrapped DEK
	tamperedEnv := *env
	rawDEK, _ := hex.DecodeString(tamperedEnv.WrappedDEKHex)
	rawDEK[0] ^= 0x01
	tamperedEnv.WrappedDEKHex = hex.EncodeToString(rawDEK)
	_, err = vault.DecryptEnvelope(&tamperedEnv, context)
	if err == nil || !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("expected AUTHENTICATION_FAILED on tampered wrapped DEK, got: %v", err)
	}

	// 3. Tampered ciphertext payload
	tamperedEnv2 := *env
	rawCT, _ := hex.DecodeString(tamperedEnv2.CiphertextHex)
	rawCT[0] ^= 0x01
	tamperedEnv2.CiphertextHex = hex.EncodeToString(rawCT)
	_, err = vault.DecryptEnvelope(&tamperedEnv2, context)
	if err == nil || !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("expected AUTHENTICATION_FAILED on tampered ciphertext, got: %v", err)
	}

	// 4. Tampered DEK nonce
	tamperedEnv3 := *env
	rawNonceDEK, _ := hex.DecodeString(tamperedEnv3.NonceDEKHex)
	rawNonceDEK[0] ^= 0x01
	tamperedEnv3.NonceDEKHex = hex.EncodeToString(rawNonceDEK)
	_, err = vault.DecryptEnvelope(&tamperedEnv3, context)
	if err == nil || !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("expected AUTHENTICATION_FAILED on tampered DEK nonce, got: %v", err)
	}
}

func TestEnvelopeKeyRotationAndRewrap(t *testing.T) {
	vault := kms.NewKMSVault()
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	shares, _ := kms.SplitSecret(masterKey, 2, 3)
	vault.UnsealWithShares(shares[:2])

	plaintext := []byte("ZERO_EXPOSURE_KEY_ROTATION_PAYLOAD")
	context := map[string]string{"env": "staging"}
	keyID := "rotation-keyring"

	// Encrypt under v1
	envV1, err := vault.EncryptEnvelope(keyID, plaintext, context)
	if err != nil {
		t.Fatalf("EncryptEnvelope failed: %v", err)
	}
	if envV1.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", envV1.KeyVersion)
	}

	// Rotate key: increments version to 2
	newVer, err := vault.RotateKeyVersion(keyID)
	if err != nil {
		t.Fatalf("RotateKeyVersion failed: %v", err)
	}
	if newVer != 2 {
		t.Fatalf("expected rotated version 2, got %d", newVer)
	}

	// Old envelope still decrypts under historical KEK v1
	decryptedV1, err := vault.DecryptEnvelope(envV1, context)
	if err != nil {
		t.Fatalf("DecryptEnvelope with historical v1 failed: %v", err)
	}
	if !bytes.Equal(decryptedV1, plaintext) {
		t.Fatal("decryptedV1 plaintext mismatch")
	}

	// Rewrap envelope to v2
	envV2, err := vault.RewrapEnvelope(envV1, context)
	if err != nil {
		t.Fatalf("RewrapEnvelope failed: %v", err)
	}
	if envV2.KeyVersion != 2 {
		t.Fatalf("expected rewrapped version 2, got %d", envV2.KeyVersion)
	}

	// CRITICAL MANDATE: CiphertextHex MUST remain byte-for-byte identical (no bulk re-encryption)
	if envV2.CiphertextHex != envV1.CiphertextHex {
		t.Fatalf("bulk ciphertext was altered during rewrap!\nv1: %s\nv2: %s", envV1.CiphertextHex, envV2.CiphertextHex)
	}
	if envV2.NoncePayloadHex != envV1.NoncePayloadHex {
		t.Fatal("payload nonce was altered during rewrap")
	}

	// Wrapped DEK must be newly generated and wrapped under v2
	if envV2.WrappedDEKHex == envV1.WrappedDEKHex {
		t.Fatal("wrapped DEK should have changed upon rewrap to new version")
	}

	// Decrypt rewrapped envelope under v2
	decryptedV2, err := vault.DecryptEnvelope(envV2, context)
	if err != nil {
		t.Fatalf("DecryptEnvelope with rewrapped v2 failed: %v", err)
	}
	if !bytes.Equal(decryptedV2, plaintext) {
		t.Fatal("decryptedV2 plaintext mismatch")
	}
}

func TestZeroizeBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	kms.ZeroizeBytes(buf)
	for i, v := range buf {
		if v != 0 {
			t.Fatalf("byte at index %d was not zeroized (val: %d)", i, v)
		}
	}
}

// =========================================================================
// 4. Auditor 10-Rule Posture & Score Calculation Tests
// =========================================================================

func TestAuditorHardenedPolicy100Score(t *testing.T) {
	policy, err := kms.LoadPolicyFromFile("../../fixtures/hardened_kms_policy.json")
	if err != nil {
		t.Fatalf("failed to load hardened_kms_policy.json: %v", err)
	}

	report := kms.EvaluatePolicy(policy)
	if report.PostureScore != 100 {
		t.Fatalf("expected posture score 100, got %d", report.PostureScore)
	}
	if report.Status != "PASS" {
		t.Fatalf("expected status PASS, got %s", report.Status)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	if report.PassedRules != 10 || report.FailedRules != 0 {
		t.Fatalf("expected 10 passed, 0 failed; got %d passed, %d failed", report.PassedRules, report.FailedRules)
	}
}

func TestAuditorVulnerablePolicy0Score(t *testing.T) {
	policy, err := kms.LoadPolicyFromFile("../../fixtures/vulnerable_kms_policy.json")
	if err != nil {
		t.Fatalf("failed to load vulnerable_kms_policy.json: %v", err)
	}

	report := kms.EvaluatePolicy(policy)
	if report.PostureScore != 0 {
		t.Fatalf("expected posture score 0, got %d", report.PostureScore)
	}
	if report.Status != "FAIL" {
		t.Fatalf("expected status FAIL, got %s", report.Status)
	}
	if len(report.Findings) != 10 {
		t.Fatalf("expected 10 findings, got %d", len(report.Findings))
	}
	if report.Deductions != 124 {
		t.Fatalf("expected total deductions 124, got %d", report.Deductions)
	}

	// Verify all 10 rule IDs triggered
	expectedRuleIDs := []string{
		"LH-KMS-001", "LH-KMS-002", "LH-KMS-003", "LH-KMS-004", "LH-KMS-005",
		"LH-KMS-006", "LH-KMS-007", "LH-KMS-008", "LH-KMS-009", "LH-KMS-010",
	}
	foundMap := make(map[string]bool)
	for _, f := range report.Findings {
		foundMap[f.RuleID] = true
	}
	for _, id := range expectedRuleIDs {
		if !foundMap[id] {
			t.Errorf("missing expected rule violation: %s", id)
		}
	}
}

func getBaseHardenedPolicy() *kms.KMSPolicy {
	return &kms.KMSPolicy{
		PolicyID:                       "TEST-POL",
		PolicyName:                     "Test Policy",
		Organization:                   "Logihertz Systems",
		ShamirUnsealRequired:           true,
		ShamirThresholdM:               3,
		ShamirTotalSharesN:             5,
		AllowPlaintextRootKeyFile:      false,
		AEADCipher:                     "AES-256-GCM",
		DEKKeyBits:                     256,
		RequireMTLSClientAuth:          true,
		AllowUnauthenticatedKMSRPC:     false,
		RequireEncryptionContextAAD:    true,
		AutoKeyRotationEnabled:         true,
		KeyRotationIntervalDays:        60,
		MlockKeyMemory:                 true,
		ZeroizeDEKAfterOp:              true,
		DisableOSSwap:                  true,
		VerifyCSPRNGHealthOnBoot:       true,
		MaxInvocationsPerKEKVersion:    10000000,
		AllowRawKEKExport:              false,
		EnforceLeastPrivilegeKeyGrants: true,
		MinKeyDeletionWindowDays:       14,
		AutoSealOnIntrusionAlert:       true,
		HashChainedKMSAuditLog:         true,
	}
}

func TestAuditorIndividualRules(t *testing.T) {
	// Rule 1: CRITICAL (-25)
	p1 := getBaseHardenedPolicy()
	p1.ShamirUnsealRequired = false
	r1 := kms.EvaluatePolicy(p1)
	if r1.PostureScore != 75 || len(r1.Findings) != 1 || r1.Findings[0].RuleID != "LH-KMS-001" {
		t.Fatalf("Rule 1 failed: score=%d, findings=%d", r1.PostureScore, len(r1.Findings))
	}

	// Rule 2: CRITICAL (-25)
	p2 := getBaseHardenedPolicy()
	p2.AEADCipher = "AES-CBC"
	r2 := kms.EvaluatePolicy(p2)
	if r2.PostureScore != 75 || len(r2.Findings) != 1 || r2.Findings[0].RuleID != "LH-KMS-002" {
		t.Fatalf("Rule 2 failed: score=%d, findings=%d", r2.PostureScore, len(r2.Findings))
	}

	// Rule 3: CRITICAL (-25)
	p3 := getBaseHardenedPolicy()
	p3.RequireMTLSClientAuth = false
	r3 := kms.EvaluatePolicy(p3)
	if r3.PostureScore != 75 || len(r3.Findings) != 1 || r3.Findings[0].RuleID != "LH-KMS-003" {
		t.Fatalf("Rule 3 failed: score=%d, findings=%d", r3.PostureScore, len(r3.Findings))
	}

	// Rule 4: HIGH (-10)
	p4 := getBaseHardenedPolicy()
	p4.RequireEncryptionContextAAD = false
	r4 := kms.EvaluatePolicy(p4)
	if r4.PostureScore != 90 || len(r4.Findings) != 1 || r4.Findings[0].RuleID != "LH-KMS-004" {
		t.Fatalf("Rule 4 failed: score=%d, findings=%d", r4.PostureScore, len(r4.Findings))
	}

	// Rule 5: HIGH (-10)
	p5 := getBaseHardenedPolicy()
	p5.AutoKeyRotationEnabled = false
	r5 := kms.EvaluatePolicy(p5)
	if r5.PostureScore != 90 || len(r5.Findings) != 1 || r5.Findings[0].RuleID != "LH-KMS-005" {
		t.Fatalf("Rule 5 failed: score=%d, findings=%d", r5.PostureScore, len(r5.Findings))
	}

	// Rule 6: HIGH (-10)
	p6 := getBaseHardenedPolicy()
	p6.MlockKeyMemory = false
	r6 := kms.EvaluatePolicy(p6)
	if r6.PostureScore != 90 || len(r6.Findings) != 1 || r6.Findings[0].RuleID != "LH-KMS-006" {
		t.Fatalf("Rule 6 failed: score=%d, findings=%d", r6.PostureScore, len(r6.Findings))
	}

	// Rule 7: HIGH (-10)
	p7 := getBaseHardenedPolicy()
	p7.VerifyCSPRNGHealthOnBoot = false
	r7 := kms.EvaluatePolicy(p7)
	if r7.PostureScore != 90 || len(r7.Findings) != 1 || r7.Findings[0].RuleID != "LH-KMS-007" {
		t.Fatalf("Rule 7 failed: score=%d, findings=%d", r7.PostureScore, len(r7.Findings))
	}

	// Rule 8: MEDIUM (-4)
	p8 := getBaseHardenedPolicy()
	p8.AllowRawKEKExport = true
	r8 := kms.EvaluatePolicy(p8)
	if r8.PostureScore != 96 || len(r8.Findings) != 1 || r8.Findings[0].RuleID != "LH-KMS-008" {
		t.Fatalf("Rule 8 failed: score=%d, findings=%d", r8.PostureScore, len(r8.Findings))
	}

	// Rule 9: MEDIUM (-4)
	p9 := getBaseHardenedPolicy()
	p9.MinKeyDeletionWindowDays = 3
	r9 := kms.EvaluatePolicy(p9)
	if r9.PostureScore != 96 || len(r9.Findings) != 1 || r9.Findings[0].RuleID != "LH-KMS-009" {
		t.Fatalf("Rule 9 failed: score=%d, findings=%d", r9.PostureScore, len(r9.Findings))
	}

	// Rule 10: LOW (-1)
	p10 := getBaseHardenedPolicy()
	p10.HashChainedKMSAuditLog = false
	r10 := kms.EvaluatePolicy(p10)
	if r10.PostureScore != 99 || len(r10.Findings) != 1 || r10.Findings[0].RuleID != "LH-KMS-010" {
		t.Fatalf("Rule 10 failed: score=%d, findings=%d", r10.PostureScore, len(r10.Findings))
	}

	// Partial compound score: 1 CRITICAL + 1 HIGH = 100 - 35 = 65
	pCombo := getBaseHardenedPolicy()
	pCombo.ShamirUnsealRequired = false
	pCombo.RequireEncryptionContextAAD = false
	rCombo := kms.EvaluatePolicy(pCombo)
	if rCombo.PostureScore != 65 || len(rCombo.Findings) != 2 {
		t.Fatalf("Compound score failed: score=%d, findings=%d", rCombo.PostureScore, len(rCombo.Findings))
	}
}

// =========================================================================
// 5. Exporters (Table, JSON, SARIF v2.1.0) Tests
// =========================================================================

func TestExportersTableJSONSarif(t *testing.T) {
	policy := getBaseHardenedPolicy()
	report := kms.EvaluatePolicy(policy)

	// Table export
	tbl := kms.ExportTable(report)
	if !strings.Contains(tbl, "LOGIHERTZ SOVEREIGN KMS") {
		t.Fatal("Table output missing header")
	}
	if !strings.Contains(tbl, "100/100 [PASS]") {
		t.Fatal("Table output missing PASS score banner")
	}

	// JSON export
	jsonStr, err := kms.ExportJSON(report)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	if !strings.Contains(jsonStr, `"posture_score": 100`) {
		t.Fatal("JSON output missing posture_score 100")
	}

	// SARIF export
	sarifStr, err := kms.ExportSARIF(report)
	if err != nil {
		t.Fatalf("ExportSARIF failed: %v", err)
	}
	if !strings.Contains(sarifStr, "sarif-schema-2.1.0.json") {
		t.Fatal("SARIF output missing schema URI")
	}
	if !strings.Contains(sarifStr, `"name": "lh-kms"`) {
		t.Fatal("SARIF output missing tool driver name lh-kms")
	}
}

// =========================================================================
// 6. Subprocess CLI Invocation Tests
// =========================================================================

func getGoBinary() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	if _, err := os.Stat("/tmp/go/bin/go"); err == nil {
		return "/tmp/go/bin/go"
	}
	return "go"
}

func getBinPath(t *testing.T) string {
	if p := os.Getenv("LH_KMS_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "../.."))
	binPath := filepath.Join(repoRoot, "bin", "lh-kms")

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		os.MkdirAll(filepath.Join(repoRoot, "bin"), 0755)
		cmd := exec.Command(getGoBinary(), "build", "-o", binPath, "./cmd/lh-kms")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to build lh-kms binary: %v\nOutput: %s", err, string(out))
		}
	}
	return binPath
}

func TestCLIVersionAndHelp(t *testing.T) {
	bin := getBinPath(t)

	// --version
	cmd := exec.Command(bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "lh-kms v0.1.0") {
		t.Fatalf("unexpected version output: %s", string(out))
	}

	// --help
	cmdHelp := exec.Command(bin, "--help")
	outHelp, err := cmdHelp.CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\nOutput: %s", err, string(outHelp))
	}
	if !strings.Contains(string(outHelp), "USAGE:") {
		t.Fatalf("unexpected help output: %s", string(outHelp))
	}
}

func TestCLIScanHardenedAndVulnerable(t *testing.T) {
	bin := getBinPath(t)
	wd, _ := os.Getwd()
	repoRoot := filepath.Clean(filepath.Join(wd, "../.."))

	// Hardened policy: exit code 0
	cmdHardened := exec.Command(bin, "scan", filepath.Join(repoRoot, "fixtures", "hardened_kms_policy.json"))
	outHardened, err := cmdHardened.CombinedOutput()
	if err != nil {
		t.Fatalf("scan hardened policy failed: %v\nOutput: %s", err, string(outHardened))
	}
	if !strings.Contains(string(outHardened), "100/100 [PASS]") {
		t.Fatalf("expected 100/100 PASS in output: %s", string(outHardened))
	}

	// Vulnerable policy: exit code 1
	cmdVuln := exec.Command(bin, "scan", filepath.Join(repoRoot, "fixtures", "vulnerable_kms_policy.json"))
	outVuln, err := cmdVuln.CombinedOutput()
	if err == nil {
		t.Fatal("scan vulnerable policy should exit with code 1")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %v\nOutput: %s", err, string(outVuln))
	}
	if !strings.Contains(string(outVuln), "0/100 [FAIL]") {
		t.Fatalf("expected 0/100 FAIL in output: %s", string(outVuln))
	}
}

func TestCLIScanFormatsAndOutputFile(t *testing.T) {
	bin := getBinPath(t)
	wd, _ := os.Getwd()
	repoRoot := filepath.Clean(filepath.Join(wd, "../.."))
	tmpDir := t.TempDir()

	// JSON format
	cmdJSON := exec.Command(bin, "scan", filepath.Join(repoRoot, "fixtures", "hardened_kms_policy.json"), "--format", "json")
	outJSON, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("scan --format json failed: %v\nOutput: %s", err, string(outJSON))
	}
	if !strings.Contains(string(outJSON), `"posture_score": 100`) {
		t.Fatal("expected posture_score: 100 in JSON")
	}

	// SARIF format to file
	sarifFile := filepath.Join(tmpDir, "report.sarif")
	cmdSARIF := exec.Command(bin, "scan", filepath.Join(repoRoot, "fixtures", "hardened_kms_policy.json"), "--format", "sarif", "--output", sarifFile)
	outSARIF, err := cmdSARIF.CombinedOutput()
	if err != nil {
		t.Fatalf("scan --format sarif --output failed: %v\nOutput: %s", err, string(outSARIF))
	}
	savedSARIF, err := os.ReadFile(sarifFile)
	if err != nil {
		t.Fatalf("failed to read saved SARIF file: %v", err)
	}
	if !strings.Contains(string(savedSARIF), "sarif-schema-2.1.0.json") {
		t.Fatal("saved SARIF file missing schema")
	}
}

func TestCLIShamirCombineCommand(t *testing.T) {
	bin := getBinPath(t)
	wd, _ := os.Getwd()
	repoRoot := filepath.Clean(filepath.Join(wd, "../.."))

	cmd := exec.Command(bin, "shamir-combine", filepath.Join(repoRoot, "fixtures", "sample_shamir_shares.json"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shamir-combine failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "SHAMIR THRESHOLD QUORUM VERIFIED") {
		t.Fatalf("unexpected shamir-combine output: %s", string(out))
	}
}

func TestCLIEnvelopeDemoCommand(t *testing.T) {
	bin := getBinPath(t)
	wd, _ := os.Getwd()
	repoRoot := filepath.Clean(filepath.Join(wd, "../.."))

	cmd := exec.Command(bin, "envelope-demo", filepath.Join(repoRoot, "fixtures", "sample_envelope_request.json"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("envelope-demo failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "SOVEREIGN KMS ENVELOPE LIFECYCLE DEMO COMPLETED SUCCESSFULLY") {
		t.Fatalf("unexpected envelope-demo output: %s", string(out))
	}
}

func TestCLIInvalidCommandExitCode2(t *testing.T) {
	bin := getBinPath(t)

	cmd := exec.Command(bin, "nonexistent-command")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected exit error for invalid subcommand")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %v\nOutput: %s", err, string(out))
	}
}
