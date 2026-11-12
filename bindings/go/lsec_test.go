package lsec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVersion(t *testing.T) {
	maj, min, patch := Version()
	if maj != 0 || min != 2 || patch != 0 {
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

func TestProcessHarden(t *testing.T) {
	if err := ProcessHarden(); err != nil {
		t.Fatalf("ProcessHarden failed: %v", err)
	}
}

func TestMultiVaultFlow(t *testing.T) {
	payload := []byte("go multi-vault payload data")
	pass0 := []byte("go-owner-passphrase")
	pass1 := []byte("go-recovery-credential")

	container, err := MultiVaultCreate(payload, pass0, CipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("MultiVaultCreate failed: %v", err)
	}
	if len(container) < 367 {
		t.Fatalf("expected container len >= 367, got %d", len(container))
	}

	slots, err := MultiVaultActiveSlots(container)
	if err != nil {
		t.Fatalf("MultiVaultActiveSlots failed: %v", err)
	}
	if slots != [4]bool{true, false, false, false} {
		t.Fatalf("expected slot 0 active, got %v", slots)
	}

	slotIdx, err := MultiVaultAddSlot(container, pass0, pass1, CipherAES256GCM)
	if err != nil {
		t.Fatalf("MultiVaultAddSlot failed: %v", err)
	}
	if slotIdx != 1 {
		t.Fatalf("expected slot index 1, got %d", slotIdx)
	}

	slots, err = MultiVaultActiveSlots(container)
	if err != nil {
		t.Fatalf("MultiVaultActiveSlots failed: %v", err)
	}
	if slots != [4]bool{true, true, false, false} {
		t.Fatalf("expected slots 0 and 1 active, got %v", slots)
	}

	opened, err := MultiVaultOpen(container, pass1)
	if err != nil {
		t.Fatalf("MultiVaultOpen with pass1 failed: %v", err)
	}
	defer opened.Free()
	if !bytes.Equal(opened.Bytes(), payload) {
		t.Fatalf("expected opened %q, got %q", payload, opened.Bytes())
	}

	updatedPayload := []byte("go multi-vault payload updated fast")
	updatedContainer, err := MultiVaultUpdatePayload(container, pass0, updatedPayload)
	if err != nil {
		t.Fatalf("MultiVaultUpdatePayload failed: %v", err)
	}

	// test transparent routing through standard Unseal
	unsealed, err := Unseal(updatedContainer, pass1)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	defer unsealed.Free()
	if !bytes.Equal(unsealed.Bytes(), updatedPayload) {
		t.Fatalf("expected unsealed %q, got %q", updatedPayload, unsealed.Bytes())
	}

	if err := MultiVaultRemoveSlot(updatedContainer, pass0, 1); err != nil {
		t.Fatalf("MultiVaultRemoveSlot failed: %v", err)
	}

	_, err = MultiVaultOpen(updatedContainer, pass1)
	if err == nil {
		t.Fatalf("expected open with removed slot to fail")
	}
}

