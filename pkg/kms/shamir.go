package kms

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// Galois Field GF(2^8) lookup tables using primitive irreducible polynomial:
// P(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
// Generator alpha = 2
var (
	gfExp [510]byte
	gfLog [256]byte
)

func init() {
	poly := 0x11D
	val := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(val)
		gfExp[i+255] = byte(val)
		gfLog[val] = byte(i)
		val <<= 1
		if val&0x100 != 0 {
			val ^= poly
		}
	}
	gfLog[0] = 0 // log(0) undefined, mapped to 0
}

// GF256Mul multiplies two elements in GF(2^8).
func GF256Mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	idx := int(gfLog[a]) + int(gfLog[b])
	return gfExp[idx]
}

// GF256Div divides element a by element b in GF(2^8).
func GF256Div(a, b byte) (byte, error) {
	if b == 0 {
		return 0, errors.New("GF(2^8) division by zero")
	}
	if a == 0 {
		return 0, nil
	}
	idx := (int(gfLog[a]) - int(gfLog[b]) + 255) % 255
	return gfExp[idx], nil
}

// GF256Inv computes the multiplicative inverse in GF(2^8).
func GF256Inv(a byte) (byte, error) {
	if a == 0 {
		return 0, errors.New("zero has no multiplicative inverse in GF(2^8)")
	}
	return gfExp[255-int(gfLog[a])], nil
}

// ShamirShare represents a single threshold share with verifiable commitment metadata.
type ShamirShare struct {
	Index                  int    `json:"index"`
	Threshold              int    `json:"threshold"`
	TotalShares            int    `json:"total_shares"`
	ShareBytesHex          string `json:"share_bytes_hex"`
	SecretCommitmentSHA256 string `json:"secret_commitment_sha256"`
}

// ShamirShareManifest packages multiple shares with metadata for serialization.
type ShamirShareManifest struct {
	Version                string        `json:"version"`
	Threshold              int           `json:"threshold"`
	TotalShares            int           `json:"total_shares"`
	SecretCommitmentSHA256 string        `json:"secret_commitment_sha256"`
	Shares                 []ShamirShare `json:"shares"`
}

// ComputeSecretCommitment calculates the domain-separated SHA-256 commitment of the secret.
func ComputeSecretCommitment(secret []byte) string {
	h := sha256.New()
	h.Write([]byte("LH_SHAMIR_COMMIT:"))
	h.Write(secret)
	return hex.EncodeToString(h.Sum(nil))
}

// SplitSecret splits secret bytes into N shares requiring M shares for reconstruction.
func SplitSecret(secret []byte, threshold, totalShares int) ([]ShamirShare, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold M (%d) must be at least 2", threshold)
	}
	if totalShares < threshold {
		return nil, fmt.Errorf("total shares N (%d) must be greater than or equal to threshold M (%d)", totalShares, threshold)
	}
	if totalShares > 255 {
		return nil, fmt.Errorf("total shares N (%d) exceeds maximum GF(2^8) coordinates (255)", totalShares)
	}

	secretLen := len(secret)
	commitment := ComputeSecretCommitment(secret)

	// Allocate share buffers for x = 1 .. totalShares
	shareRaw := make([][]byte, totalShares)
	for i := range shareRaw {
		shareRaw[i] = make([]byte, secretLen)
	}

	// For each byte position in secret, evaluate polynomial with random coefficients
	for b := 0; b < secretLen; b++ {
		coeffs := make([]byte, threshold)
		coeffs[0] = secret[b]

		// Draw M-1 random coefficients from CSPRNG
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("failed to read random bytes for polynomial coefficients: %w", err)
		}

		// Evaluate polynomial at each x_i = i+1 in {1 .. totalShares}
		for i := 0; i < totalShares; i++ {
			x := byte(i + 1)
			// Horner's method in GF(2^8)
			y := coeffs[threshold-1]
			for k := threshold - 2; k >= 0; k-- {
				y = GF256Mul(y, x) ^ coeffs[k]
			}
			shareRaw[i][b] = y
		}
	}

	shares := make([]ShamirShare, totalShares)
	for i := 0; i < totalShares; i++ {
		shares[i] = ShamirShare{
			Index:                  i + 1,
			Threshold:              threshold,
			TotalShares:            totalShares,
			ShareBytesHex:          hex.EncodeToString(shareRaw[i]),
			SecretCommitmentSHA256: commitment,
		}
	}

	return shares, nil
}

// CombineShares reconstructs the original secret using Lagrange polynomial interpolation at x = 0.
func CombineShares(shares []ShamirShare) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	threshold := shares[0].Threshold
	if threshold < 2 {
		return nil, fmt.Errorf("invalid share threshold: %d", threshold)
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("INSUFFICIENT_SHAMIR_SHARES: provided %d shares, threshold requires %d", len(shares), threshold)
	}

	expectedCommitment := shares[0].SecretCommitmentSHA256

	// Deduplicate shares by index and take first M distinct shares
	seenIndices := make(map[int]bool)
	type decodedShare struct {
		x     byte
		bytes []byte
	}
	var selected []decodedShare

	for _, s := range shares {
		if s.Index < 1 || s.Index > 255 {
			return nil, fmt.Errorf("invalid share index %d (must be in 1..255)", s.Index)
		}
		if s.Threshold != threshold {
			return nil, fmt.Errorf("mismatched share threshold: expected %d, got %d", threshold, s.Threshold)
		}
		if s.SecretCommitmentSHA256 != expectedCommitment {
			return nil, errors.New("mismatched secret commitment across shares")
		}
		if seenIndices[s.Index] {
			continue // ignore duplicate shares of the same index
		}
		seenIndices[s.Index] = true

		rawBytes, err := hex.DecodeString(s.ShareBytesHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share %d hex: %w", s.Index, err)
		}
		selected = append(selected, decodedShare{
			x:     byte(s.Index),
			bytes: rawBytes,
		})

		if len(selected) == threshold {
			break
		}
	}

	if len(selected) < threshold {
		return nil, fmt.Errorf("INSUFFICIENT_SHAMIR_SHARES: only %d unique shares provided, need %d", len(selected), threshold)
	}

	secretLen := len(selected[0].bytes)
	for i := 1; i < threshold; i++ {
		if len(selected[i].bytes) != secretLen {
			return nil, errors.New("mismatched share byte lengths")
		}
	}

	// Compute Lagrange basis polynomials at x = 0:
	// l_j(0) = \prod_{m != j} (x_m / (x_j ^ x_m))
	basis := make([]byte, threshold)
	for j := 0; j < threshold; j++ {
		l := byte(1)
		for m := 0; m < threshold; m++ {
			if m == j {
				continue
			}
			num := selected[m].x
			den := selected[j].x ^ selected[m].x
			if den == 0 {
				return nil, errors.New("duplicate share coordinates encountered")
			}
			ratio, err := GF256Div(num, den)
			if err != nil {
				return nil, err
			}
			l = GF256Mul(l, ratio)
		}
		basis[j] = l
	}

	// Interpolate secret byte-by-byte
	reconstructed := make([]byte, secretLen)
	for b := 0; b < secretLen; b++ {
		var val byte
		for j := 0; j < threshold; j++ {
			term := GF256Mul(selected[j].bytes[b], basis[j])
			val ^= term
		}
		reconstructed[b] = val
	}

	// Verify constant-time SHA-256 commitment
	computedCommitment := ComputeSecretCommitment(reconstructed)
	if subtle.ConstantTimeCompare([]byte(computedCommitment), []byte(expectedCommitment)) != 1 {
		// Zeroize reconstructed memory before returning error
		for i := range reconstructed {
			reconstructed[i] = 0
		}
		return nil, errors.New("SHAMIR_COMMITMENT_MISMATCH: reconstructed secret does not match commitment (tampered or corrupt share)")
	}

	return reconstructed, nil
}
