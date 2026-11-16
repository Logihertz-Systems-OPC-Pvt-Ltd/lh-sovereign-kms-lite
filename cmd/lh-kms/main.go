package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite/pkg/kms"
)

const version = "0.1.0"

func printUsage() {
	fmt.Printf(`Logihertz Sovereign KMS Lite (lh-kms) v%s
Production-grade On-Premise Envelope KMS, GF(2^8) Shamir (M, N) Unseal Engine,
AES-256-GCM Envelope Encryptor, Key Rotator & 10-Rule Posture Auditor.

USAGE:
  lh-kms <subcommand> [flags] [arguments]

SUBCOMMANDS:
  scan <policy.json> [--format table|json|sarif] [--output <file>]
      Audit a KMS security policy manifest against the 10 normative rules.
      Exits 0 if posture score is 100/100, 1 on policy violations, 2 on error.

  shamir-split --secret-hex <hex> [--threshold 3] [--shares 5] [--output <file>]
      Split a 256-bit (32-byte) secret into N verifiable shares requiring M threshold.

  shamir-combine <shares.json>
      Reconstruct the 256-bit secret from a JSON manifest containing threshold shares.

  envelope-demo <envelope_request.json>
      Run an end-to-end envelope encryption, KEK rotation, rewrap, and seal demo.

  --version, version
      Display the current version and build attribution.

  --help, help
      Display this usage and help documentation.

EXIT CODES:
  0   Success / Policy Pass / Verified Reconstruction / Complete Demo Lifecycle
  1   Policy Violation / Commitment Mismatch / AAD Authentication Failure
  2   CLI Syntax Error / Missing File / Invalid Parameter
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]

	switch cmd {
	case "--version", "-v", "version":
		fmt.Printf("lh-kms v%s (Logihertz Sovereign KMS Lite)\n", version)
		os.Exit(0)

	case "--help", "-h", "help":
		printUsage()
		os.Exit(0)

	case "scan":
		runScan(os.Args[2:])

	case "shamir-split":
		runShamirSplit(os.Args[2:])

	case "shamir-combine":
		runShamirCombine(os.Args[2:])

	case "envelope-demo":
		runEnvelopeDemo(os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand '%s'\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func runScan(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: scan requires a path to a policy JSON file")
		os.Exit(2)
	}

	policyPath := ""
	format := "table"
	outputPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		} else if arg == "--output" && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--output=") {
			outputPath = strings.TrimPrefix(arg, "--output=")
		} else if !strings.HasPrefix(arg, "--") && policyPath == "" {
			policyPath = arg
		} else {
			fmt.Fprintf(os.Stderr, "Error: unknown or unexpected argument '%s'\n", arg)
			os.Exit(2)
		}
	}

	if policyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: policy JSON path is required")
		os.Exit(2)
	}

	policy, err := kms.LoadPolicyFromFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
		os.Exit(2)
	}

	report := kms.EvaluatePolicy(policy)

	var output string
	switch strings.ToLower(format) {
	case "table":
		output = kms.ExportTable(report)
	case "json":
		jsonOut, err := kms.ExportJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			os.Exit(2)
		}
		output = jsonOut
	case "sarif":
		sarifOut, err := kms.ExportSARIF(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating SARIF: %v\n", err)
			os.Exit(2)
		}
		output = sarifOut
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported format '%s' (valid: table, json, sarif)\n", format)
		os.Exit(2)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(2)
		}
	} else {
		fmt.Println(output)
	}

	if report.Status == "PASS" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func runShamirSplit(args []string) {
	secretHex := ""
	threshold := 3
	shares := 5
	outputPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--secret-hex" && i+1 < len(args) {
			secretHex = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--secret-hex=") {
			secretHex = strings.TrimPrefix(arg, "--secret-hex=")
		} else if arg == "--threshold" && i+1 < len(args) {
			val, err := strconv.Atoi(args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid threshold: %v\n", err)
				os.Exit(2)
			}
			threshold = val
			i++
		} else if strings.HasPrefix(arg, "--threshold=") {
			val, err := strconv.Atoi(strings.TrimPrefix(arg, "--threshold="))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid threshold: %v\n", err)
				os.Exit(2)
			}
			threshold = val
		} else if arg == "--shares" && i+1 < len(args) {
			val, err := strconv.Atoi(args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid shares count: %v\n", err)
				os.Exit(2)
			}
			shares = val
			i++
		} else if strings.HasPrefix(arg, "--shares=") {
			val, err := strconv.Atoi(strings.TrimPrefix(arg, "--shares="))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid shares count: %v\n", err)
				os.Exit(2)
			}
			shares = val
		} else if arg == "--output" && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--output=") {
			outputPath = strings.TrimPrefix(arg, "--output=")
		} else {
			fmt.Fprintf(os.Stderr, "Error: unknown argument '%s'\n", arg)
			os.Exit(2)
		}
	}

	if secretHex == "" {
		fmt.Fprintln(os.Stderr, "Error: --secret-hex is required")
		os.Exit(2)
	}

	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid secret hex string: %v\n", err)
		os.Exit(2)
	}

	splitShares, err := kms.SplitSecret(secretBytes, threshold, shares)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error splitting secret: %v\n", err)
		os.Exit(2)
	}

	manifest := kms.ShamirShareManifest{
		Version:                version,
		Threshold:              threshold,
		TotalShares:            shares,
		SecretCommitmentSHA256: splitShares[0].SecretCommitmentSHA256,
		Shares:                 splitShares,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding shares manifest: %v\n", err)
		os.Exit(2)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, manifestBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing shares file: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Successfully generated %d-of-%d Shamir shares to %s\n", threshold, shares, outputPath)
	} else {
		fmt.Println(string(manifestBytes))
	}

	os.Exit(0)
}

func runShamirCombine(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: shamir-combine requires a path to a shares JSON file")
		os.Exit(2)
	}

	sharesFile := args[0]
	data, err := os.ReadFile(sharesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading shares file: %v\n", err)
		os.Exit(2)
	}

	var manifest kms.ShamirShareManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing shares JSON: %v\n", err)
		os.Exit(2)
	}

	reconstructed, err := kms.CombineShares(manifest.Shares)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to reconstruct secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] SHAMIR THRESHOLD QUORUM VERIFIED\n")
	fmt.Printf("    Threshold M:           %d\n", manifest.Threshold)
	fmt.Printf("    Total Shares N:        %d\n", manifest.TotalShares)
	fmt.Printf("    Reconstructed Length:  %d bytes (256-bit key)\n", len(reconstructed))
	fmt.Printf("    Reconstructed Secret:  %s\n", hex.EncodeToString(reconstructed))
	fmt.Printf("    SHA-256 Commitment:    %s\n", manifest.SecretCommitmentSHA256)
	os.Exit(0)
}

type envelopeDemoRequest struct {
	KeyID             string            `json:"key_id"`
	Plaintext         string            `json:"plaintext"`
	EncryptionContext map[string]string `json:"encryption_context"`
}

func runEnvelopeDemo(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: envelope-demo requires a request JSON file")
		os.Exit(2)
	}

	reqFile := args[0]
	data, err := os.ReadFile(reqFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request file: %v\n", err)
		os.Exit(2)
	}

	var req envelopeDemoRequest
	if err := json.Unmarshal(data, &req); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing request JSON: %v\n", err)
		os.Exit(2)
	}

	// 1. Generate ephemeral 256-bit master key and split into 3-of-5 shares
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random master key: %v\n", err)
		os.Exit(2)
	}
	defer kms.ZeroizeBytes(masterKey)

	shares, err := kms.SplitSecret(masterKey, 3, 5)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Shamir shares: %v\n", err)
		os.Exit(2)
	}

	// 2. Initialize vault and verify sealed state
	vault := kms.NewKMSVault()
	if !vault.IsSealed() {
		fmt.Fprintln(os.Stderr, "Error: new vault must start in sealed state")
		os.Exit(1)
	}

	// 3. Unseal vault using subset of shares {1, 3, 5}
	quorum := []kms.ShamirShare{shares[0], shares[2], shares[4]}
	if err := vault.UnsealWithShares(quorum); err != nil {
		fmt.Fprintf(os.Stderr, "Error unsealing vault: %v\n", err)
		os.Exit(1)
	}
	if vault.IsSealed() {
		fmt.Fprintln(os.Stderr, "Error: vault remained sealed after unseal")
		os.Exit(1)
	}

	// 4. Encrypt envelope under KEK v1
	plaintextBytes := []byte(req.Plaintext)
	envV1, err := vault.EncryptEnvelope(req.KeyID, plaintextBytes, req.EncryptionContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting envelope: %v\n", err)
		os.Exit(1)
	}

	// 5. Decrypt envelope under v1
	decryptedV1, err := vault.DecryptEnvelope(envV1, req.EncryptionContext)
	if err != nil || string(decryptedV1) != req.Plaintext {
		fmt.Fprintf(os.Stderr, "Decryption under v1 failed: %v\n", err)
		os.Exit(1)
	}

	// 6. Rotate KEK version to v2
	newVer, err := vault.RotateKeyVersion(req.KeyID)
	if err != nil || newVer != 2 {
		fmt.Fprintf(os.Stderr, "Key rotation failed: %v\n", err)
		os.Exit(1)
	}

	// 7. Rewrap envelope under KEK v2 without bulk data re-encryption
	envV2, err := vault.RewrapEnvelope(envV1, req.EncryptionContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Envelope rewrap failed: %v\n", err)
		os.Exit(1)
	}
	if envV2.KeyVersion != 2 {
		fmt.Fprintf(os.Stderr, "Rewrapped envelope version mismatch: expected 2, got %d\n", envV2.KeyVersion)
		os.Exit(1)
	}
	if envV2.CiphertextHex != envV1.CiphertextHex {
		fmt.Fprintln(os.Stderr, "Error: bulk ciphertext was modified during rewrap (must remain identical)")
		os.Exit(1)
	}

	// 8. Decrypt rewrapped envelope under v2
	decryptedV2, err := vault.DecryptEnvelope(envV2, req.EncryptionContext)
	if err != nil || string(decryptedV2) != req.Plaintext {
		fmt.Fprintf(os.Stderr, "Decryption under v2 failed: %v\n", err)
		os.Exit(1)
	}

	// 9. Seal the vault
	vault.Seal()
	if !vault.IsSealed() {
		fmt.Fprintln(os.Stderr, "Error: vault failed to seal")
		os.Exit(1)
	}

	// 10. Verify operation on sealed vault fails
	if _, err := vault.EncryptEnvelope(req.KeyID, plaintextBytes, req.EncryptionContext); err == nil {
		fmt.Fprintln(os.Stderr, "Error: operation on sealed vault unexpectedly succeeded")
		os.Exit(1)
	}

	fmt.Println("[+] SOVEREIGN KMS ENVELOPE LIFECYCLE DEMO COMPLETED SUCCESSFULLY")
	fmt.Printf("    Key ID:               %s\n", req.KeyID)
	fmt.Printf("    Initial KEK Version:  1\n")
	fmt.Printf("    Rotated KEK Version:  2\n")
	fmt.Printf("    Plaintext Length:     %d bytes\n", len(plaintextBytes))
	fmt.Printf("    Bulk Ciphertext Hex:  %s\n", envV1.CiphertextHex)
	fmt.Printf("    Rewrapped DEK Hex:    %s\n", envV2.WrappedDEKHex)
	fmt.Printf("    Vault Post-Seal:      SEALED (Memory Zeroized)\n")
	os.Exit(0)
}
