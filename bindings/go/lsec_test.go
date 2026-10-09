package lsec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVersion(t *testing.T) {
	maj, min, patch := Version()
	if maj != 0 || min != 1 || patch != 0 {
		t.Fatalf("unexpected version: %d.%d.%d", maj, min, patch)
	}
}

func TestBufferLifecycle(t *testing.T) {
	secret := []byte("confidential-go-client-secret")
	buf, err := NewBuffer(secret)
	if err != nil {
		t.Fatalf("NewBuffer failed: %v", err)
	}
	defer buf.Free()

	if buf.Len() != len(secret) {
		t.Fatalf("expected len %d, got %d", len(secret), buf.Len())
	}

	if !bytes.Equal(buf.Bytes(), secret) {
		t.Fatalf("expected bytes %q, got %q", secret, buf.Bytes())
	}

	if err := buf.Wipe(); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	expectedZeroes := make([]byte, len(secret))
	if !bytes.Equal(buf.Bytes(), expectedZeroes) {
		t.Fatalf("expected wiped buffer to be zeroed, got %q", buf.Bytes())
	}
}

func TestVaultSealAndUnseal(t *testing.T) {
	plain := []byte("user-master-seed-phrase-secret")
	pass := []byte("strong-passphrase")

	sealed, err := Seal(plain, pass, CipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if len(sealed) <= len(plain) {
		t.Fatalf("expected sealed length to exceed plain length, got %d", len(sealed))
	}

	unsealed, err := Unseal(sealed, pass)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	defer unsealed.Free()

	if !bytes.Equal(unsealed.Bytes(), plain) {
		t.Fatalf("expected unsealed %q, got %q", plain, unsealed.Bytes())
	}

	// wrong password fails
	_, err = Unseal(sealed, []byte("wrong-password"))
	if err == nil {
		t.Fatalf("expected error on unseal with wrong password")
	}
}

func TestVaultFileOperations(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test_vault.db")

	plain := []byte("offline-keyring-db-payload")
	pass := []byte("file-passphrase")

	if err := SealToFile(vaultPath, plain, pass, CipherChaCha20Poly1305); err != nil {
		t.Fatalf("SealToFile failed: %v", err)
	}

	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("expected vault file to exist: %v", err)
	}

	unsealed, err := UnsealFromFile(vaultPath, pass)
	if err != nil {
		t.Fatalf("UnsealFromFile failed: %v", err)
	}
	defer unsealed.Free()

	if !bytes.Equal(unsealed.Bytes(), plain) {
		t.Fatalf("expected unsealed %q, got %q", plain, unsealed.Bytes())
	}
}

func TestTOTPFlow(t *testing.T) {
	base32Secret := "JBSWY3DPEHPK3PXP"
	buf, err := DecodeBase32(base32Secret)
	if err != nil {
		t.Fatalf("DecodeBase32 failed: %v", err)
	}
	defer buf.Free()

	timestamp := uint64(1234567890)
	code, err := GenerateTOTP(buf.Bytes(), timestamp, 30, 6, TotpSha1)
	if err != nil {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}

	if len(code) != 6 {
		t.Fatalf("expected 6 digits, got %q", code)
	}

	valid, err := VerifyTOTP(buf.Bytes(), code, timestamp, 30, 6, 1, TotpSha1)
	if err != nil {
		t.Fatalf("VerifyTOTP failed: %v", err)
	}
	if !valid {
		t.Fatalf("expected code %s to be valid", code)
	}

	// invalid code fails
	valid, err = VerifyTOTP(buf.Bytes(), "000000", timestamp, 30, 6, 1, TotpSha1)
	if err != nil {
		t.Fatalf("VerifyTOTP with bad code failed: %v", err)
	}
	if valid {
		t.Fatalf("expected invalid code to fail")
	}
}

