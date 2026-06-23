// Package sign provides Ed25519 signing and verification for audit log entries.
//
// The signing protocol is:
//
//  1. sigPayload = append(canonicalBytes, genesisSeed...)
//  2. entryHash  = SHA256(sigPayload)          — stored in the log for B2 chain-linking
//  3. signature  = ed25519.Sign(privKey, sigPayload)  — Ed25519 signs sigPayload directly
//
// Verification reconstructs sigPayload from canonical bytes (never trusts the
// stored entryHash) and calls ed25519.Verify. This ensures a tampered record
// cannot produce a valid signature even if its stored hash is also replaced.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signer signs arbitrary payloads and reports its key identity.
type Signer interface {
	Sign(payload []byte) (sig []byte, err error)
	KeyID() string
}

// SignedEntry is the signature block stored alongside each audit log entry.
type SignedEntry struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	EntryHash string `json:"entry_hash"` // hex(SHA256(sigPayload)); used for B2 chain-linking
	Signature string `json:"signature"`  // base64(ed25519.Sign(privKey, sigPayload))
}

// Ed25519Signer signs payloads using an Ed25519 private key.
type Ed25519Signer struct {
	privKey ed25519.PrivateKey
	keyID   string
}

// NewEd25519Signer creates a Signer from an Ed25519 private key.
// KeyID is hex(SHA256(publicKeyBytes)).
func NewEd25519Signer(privKey ed25519.PrivateKey) *Ed25519Signer {
	pubKey := privKey.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pubKey)
	return &Ed25519Signer{
		privKey: privKey,
		keyID:   hex.EncodeToString(h[:]),
	}
}

// Sign signs payload directly with the Ed25519 private key.
// Ed25519 applies SHA-512 internally; the caller must NOT pre-hash.
func (s *Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, payload), nil
}

// KeyID returns the hex-encoded SHA-256 fingerprint of the signer's public key.
func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

// Verify checks that entry.Signature is a valid Ed25519 signature of sigPayload.
//
// sigPayload must be reconstructed from canonical record bytes by the caller;
// it is never derived from the stored entry.EntryHash so that a tampered record
// cannot pass verification even if its stored hash is also replaced.
func Verify(entry SignedEntry, sigPayload []byte, pubKey ed25519.PublicKey) error {
	if entry.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm: %q", entry.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if !ed25519.Verify(pubKey, sigPayload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// GenerateEd25519Key creates a new Ed25519 key pair. Intended for use in tests.
func GenerateEd25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return priv, pub, nil
}

// MarshalEd25519PrivateKeyPEM serialises priv to a PEM-encoded PKCS#8 block.
// The PEM block type is "PRIVATE KEY" (standard for PKCS#8).
func MarshalEd25519PrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8 marshal: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadEd25519PrivateKeyPEM reads and parses an Ed25519 private key from a
// PEM file containing a PKCS#8-encoded "PRIVATE KEY" block.
func LoadEd25519PrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in key file")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PEM block type %q, got %q", "PRIVATE KEY", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
	}
	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return ed25519Key, nil
}

// MarshalEd25519PublicKeyPEM serialises pub to a PEM-encoded PKIX block.
// The PEM block type is "PUBLIC KEY" (standard for PKIX/SubjectPublicKeyInfo).
func MarshalEd25519PublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("PKIX marshal: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadEd25519PublicKeyPEM reads and parses an Ed25519 public key from a
// PEM file containing a PKIX-encoded "PUBLIC KEY" block (e.g. produced by
// "openssl pkey -pubout").
func LoadEd25519PublicKeyPEM(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in public key file")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PEM block type %q, got %q", "PUBLIC KEY", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKIX public key: %w", err)
	}
	ed25519Key, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return ed25519Key, nil
}
