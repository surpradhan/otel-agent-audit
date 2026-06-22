package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519_RoundTrip(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := NewEd25519Signer(priv)

	payload := []byte("hello audit world")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	h := sha256.Sum256(payload)
	entry := SignedEntry{
		KeyID:     signer.KeyID(),
		Algorithm: "ed25519",
		EntryHash: hex.EncodeToString(h[:]),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	if err := Verify(entry, payload, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestEd25519_TamperDetected(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := NewEd25519Signer(priv)

	payload := []byte("original payload bytes")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	h := sha256.Sum256(payload)
	entry := SignedEntry{
		KeyID:     signer.KeyID(),
		Algorithm: "ed25519",
		EntryHash: hex.EncodeToString(h[:]),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	// Flip the last byte of the payload to simulate tampering.
	tampered := make([]byte, len(payload))
	copy(tampered, payload)
	tampered[len(tampered)-1] ^= 0xFF

	if err := Verify(entry, tampered, pub); err == nil {
		t.Error("Verify should have failed on tampered payload")
	}
}

func TestEd25519_WrongKey(t *testing.T) {
	privA, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key A: %v", err)
	}
	_, pubB, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key B: %v", err)
	}
	signerA := NewEd25519Signer(privA)

	payload := []byte("signed by key A")
	sig, err := signerA.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	h := sha256.Sum256(payload)
	entry := SignedEntry{
		KeyID:     signerA.KeyID(),
		Algorithm: "ed25519",
		EntryHash: hex.EncodeToString(h[:]),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	if err := Verify(entry, payload, pubB); err == nil {
		t.Error("Verify should have failed when using a different public key")
	}
}

func TestEd25519_UnsupportedAlgorithm(t *testing.T) {
	_, pub, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	entry := SignedEntry{
		Algorithm: "hmac-sha256",
		Signature: "dW5rbm93bg==",
	}
	if err := Verify(entry, []byte("payload"), pub); err == nil {
		t.Error("Verify should fail on unsupported algorithm")
	}
}

func TestPEM_RoundTrip(t *testing.T) {
	priv, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	pemBytes, err := MarshalEd25519PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM: %v", err)
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	loaded, err := LoadEd25519PrivateKeyPEM(keyFile)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKeyPEM: %v", err)
	}

	// Both keys must produce identical signatures on the same payload.
	payload := []byte("pem roundtrip check")
	sigA := ed25519.Sign(priv, payload)
	sigB := ed25519.Sign(loaded, payload)
	if string(sigA) != string(sigB) {
		t.Error("loaded key produces different signature than original key")
	}
}

func TestLoadEd25519PrivateKeyPEM_MissingFile(t *testing.T) {
	_, err := LoadEd25519PrivateKeyPEM("/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
