package kms

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// KMSPolicy represents the configuration manifest evaluated by the 10-rule posture auditor.
type KMSPolicy struct {
	PolicyID                       string `json:"policy_id"`
	PolicyName                     string `json:"policy_name"`
	Organization                   string `json:"organization"`
	ShamirUnsealRequired           bool   `json:"shamir_unseal_required"`
	ShamirThresholdM               int    `json:"shamir_threshold_m"`
	ShamirTotalSharesN             int    `json:"shamir_total_shares_n"`
	AllowPlaintextRootKeyFile      bool   `json:"allow_plaintext_root_key_file"`
	AEADCipher                     string `json:"aead_cipher"`
	DEKKeyBits                     int    `json:"dek_key_bits"`
	RequireMTLSClientAuth          bool   `json:"require_mtls_client_auth"`
	AllowUnauthenticatedKMSRPC     bool   `json:"allow_unauthenticated_kms_rpc"`
	RequireEncryptionContextAAD    bool   `json:"require_encryption_context_aad"`
	AutoKeyRotationEnabled         bool   `json:"auto_key_rotation_enabled"`
	KeyRotationIntervalDays        int    `json:"key_rotation_interval_days"`
	MlockKeyMemory                 bool   `json:"mlock_key_memory"`
	ZeroizeDEKAfterOp              bool   `json:"zeroize_dek_after_op"`
	DisableOSSwap                  bool   `json:"disable_os_swap"`
	VerifyCSPRNGHealthOnBoot       bool   `json:"verify_csprng_health_on_boot"`
	MaxInvocationsPerKEKVersion    int64  `json:"max_invocations_per_kek_version"`
	AllowRawKEKExport              bool   `json:"allow_raw_kek_export"`
	EnforceLeastPrivilegeKeyGrants bool   `json:"enforce_least_privilege_key_grants"`
	MinKeyDeletionWindowDays       int    `json:"min_key_deletion_window_days"`
	AutoSealOnIntrusionAlert       bool   `json:"auto_seal_on_intrusion_alert"`
	HashChainedKMSAuditLog         bool   `json:"hash_chained_kms_audit_log"`
}

// Finding represents a violation identified by an audit rule.
type Finding struct {
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	CWE            string `json:"cwe"`
	Deduction      int    `json:"deduction"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// AuditReport details the comprehensive posture evaluation of a KMS policy manifest.
type AuditReport struct {
	PolicyID     string    `json:"policy_id"`
	PolicyName   string    `json:"policy_name"`
	Organization string    `json:"organization"`
	Timestamp    string    `json:"timestamp"`
	PostureScore int       `json:"posture_score"`
	Status       string    `json:"status"` // PASS or FAIL
	TotalRules   int       `json:"total_rules"`
	PassedRules  int       `json:"passed_rules"`
	FailedRules  int       `json:"failed_rules"`
	Deductions   int       `json:"deductions"`
	Findings     []Finding `json:"findings"`
}

// LoadPolicyFromFile reads and parses a KMSPolicy JSON manifest.
func LoadPolicyFromFile(path string) (*KMSPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	var policy KMSPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}
	return &policy, nil
}

// EvaluatePolicy evaluates all 10 sovereign KMS rules against the given policy.
func EvaluatePolicy(policy *KMSPolicy) *AuditReport {
	report := &AuditReport{
		PolicyID:     policy.PolicyID,
		PolicyName:   policy.PolicyName,
		Organization: policy.Organization,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalRules:   10,
		Findings:     make([]Finding, 0),
	}

	totalDeductions := 0

	// Rule LH-KMS-001 (CRITICAL, CWE-321, -25)
	if !policy.ShamirUnsealRequired || policy.ShamirThresholdM < 2 || policy.ShamirTotalSharesN < 3 || policy.AllowPlaintextRootKeyFile {
		totalDeductions += 25
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-001",
			Title:          "Plaintext Root Key Exposure or Weak Shamir Unseal Quorum",
			Severity:       "CRITICAL",
			CWE:            "CWE-321",
			Deduction:      25,
			Description:    "Master root key is permitted from local plaintext file/env or Shamir threshold is less than 2-of-3 quorum.",
			Recommendation: "Enforce Shamir (M, N) threshold unseal with M >= 2 and N >= 3, and disallow plaintext root key file storage.",
		})
	}

	// Rule LH-KMS-002 (CRITICAL, CWE-327, -25)
	if (policy.AEADCipher != "AES-256-GCM" && policy.AEADCipher != "ChaCha20-Poly1305") || policy.DEKKeyBits < 256 {
		totalDeductions += 25
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-002",
			Title:          "Weak or Unauthenticated Envelope Cipher",
			Severity:       "CRITICAL",
			CWE:            "CWE-327",
			Deduction:      25,
			Description:    "KMS allows non-AEAD ciphers or DEK key length less than 256 bits, risking bit-flipping and key exhaustion.",
			Recommendation: "Mandate AES-256-GCM or ChaCha20-Poly1305 with full 256-bit symmetric keys for all envelope encryption.",
		})
	}

	// Rule LH-KMS-003 (CRITICAL, CWE-306, -25)
	if !policy.RequireMTLSClientAuth || policy.AllowUnauthenticatedKMSRPC {
		totalDeductions += 25
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-003",
			Title:          "Missing Mutual TLS (mTLS) Client Verification or Unauthenticated RPC",
			Severity:       "CRITICAL",
			CWE:            "CWE-306",
			Deduction:      25,
			Description:    "KMS network interface accepts unauthenticated requests or lacks client certificate verification (mTLS).",
			Recommendation: "Require strict mutual TLS with authorized client certificates and disallow unauthenticated KMS RPCs.",
		})
	}

	// Rule LH-KMS-004 (HIGH, CWE-345, -10)
	if !policy.RequireEncryptionContextAAD {
		totalDeductions += 10
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-004",
			Title:          "Unbound Envelope Additional Authenticated Data (AAD)",
			Severity:       "HIGH",
			CWE:            "CWE-345",
			Deduction:      10,
			Description:    "Encryption Context AAD binding is disabled, risking cross-tenant confused-deputy decryption.",
			Recommendation: "Mandate deterministic canonical AAD context binding for all envelope encrypt, decrypt, and rewrap operations.",
		})
	}

	// Rule LH-KMS-005 (HIGH, CWE-324, -10)
	if !policy.AutoKeyRotationEnabled || policy.KeyRotationIntervalDays > 90 {
		totalDeductions += 10
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-005",
			Title:          "Automated KEK Version Rotation Disabled or Excessive Interval",
			Severity:       "HIGH",
			CWE:            "CWE-324",
			Deduction:      10,
			Description:    "Key Encryption Key (KEK) rotation is disabled or rotation interval exceeds 90 days.",
			Recommendation: "Enable automated KEK version rotation with an interval of 90 days or fewer.",
		})
	}

	// Rule LH-KMS-006 (HIGH, CWE-226, -10)
	if !policy.MlockKeyMemory || !policy.ZeroizeDEKAfterOp || !policy.DisableOSSwap {
		totalDeductions += 10
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-006",
			Title:          "Missing Key Memory Locking, Swap Protection, or Immediate Zeroization",
			Severity:       "HIGH",
			CWE:            "CWE-226",
			Deduction:      10,
			Description:    "Transient DEKs and unsealed root keys are not locked in RAM, not zeroized post-operation, or OS swap is active.",
			Recommendation: "Lock process memory with mlock, disable OS swap, and zeroize transient key slices immediately after use.",
		})
	}

	// Rule LH-KMS-007 (HIGH, CWE-330, -10)
	if !policy.VerifyCSPRNGHealthOnBoot || policy.MaxInvocationsPerKEKVersion > 100000000 {
		totalDeductions += 10
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-007",
			Title:          "Missing CSPRNG Health Check or Excessive GCM Invocations",
			Severity:       "HIGH",
			CWE:            "CWE-330",
			Deduction:      10,
			Description:    "No startup CSPRNG continuous health verification or max AES-GCM invocations per KEK version exceeds 10^8.",
			Recommendation: "Verify CSPRNG continuous health on boot and limit maximum invocations per KEK version to <= 10^8.",
		})
	}

	// Rule LH-KMS-008 (MEDIUM, CWE-285, -4)
	if policy.AllowRawKEKExport || !policy.EnforceLeastPrivilegeKeyGrants {
		totalDeductions += 4
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-008",
			Title:          "Raw KEK Export Permitted or Weak Key Grant Separation",
			Severity:       "MEDIUM",
			CWE:            "CWE-285",
			Deduction:      4,
			Description:    "Policy allows raw KEK export or fails to enforce granular Encrypt/Decrypt/Rewrap permission separation.",
			Recommendation: "Disallow raw KEK export and enforce least-privilege RBAC grants for cryptographic actions.",
		})
	}

	// Rule LH-KMS-009 (MEDIUM, CWE-400, -4)
	if policy.MinKeyDeletionWindowDays < 7 || !policy.AutoSealOnIntrusionAlert {
		totalDeductions += 4
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-009",
			Title:          "Short Key Deletion Safety Window or Missing Intrusion Auto-Seal",
			Severity:       "MEDIUM",
			CWE:            "CWE-400",
			Deduction:      4,
			Description:    "Pending key deletion safety window is less than 7 days or auto-seal trigger on intrusion alarm is disabled.",
			Recommendation: "Configure at least a 7-day pending-deletion waiting period and enable automated vault sealing on tamper alerts.",
		})
	}

	// Rule LH-KMS-010 (LOW, CWE-778, -1)
	if !policy.HashChainedKMSAuditLog {
		totalDeductions += 1
		report.Findings = append(report.Findings, Finding{
			RuleID:         "LH-KMS-010",
			Title:          "Missing Hash-Chained Tamper-Evident Audit Log",
			Severity:       "LOW",
			CWE:            "CWE-778",
			Deduction:      1,
			Description:    "KMS unseal, rotation, and cryptographic operations are not logged to a tamper-evident SHA-256 hash-chain.",
			Recommendation: "Enable SHA-256 hash-chained audit logging to guarantee cryptographic non-repudiation.",
		})
	}

	score := 100 - totalDeductions
	if score < 0 {
		score = 0
	}

	report.PostureScore = score
	report.Deductions = totalDeductions
	report.FailedRules = len(report.Findings)
	report.PassedRules = report.TotalRules - report.FailedRules

	if score == 100 && report.FailedRules == 0 {
		report.Status = "PASS"
	} else {
		report.Status = "FAIL"
	}

	return report
}
