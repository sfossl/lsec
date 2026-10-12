import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tests._support import lsec, requires_lib
from lsec import CipherSuite, SecureBuffer, vault

HEADER_SIZE = 36
PLAINTEXT = b"database-encryption-key-material"
PASSPHRASE = b"correct horse battery staple"


@requires_lib
class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # argon2id runs at 64 MiB per seal, so seal each cipher once and reuse it
        cls.sealed = {cipher: vault.seal(PLAINTEXT, PASSPHRASE, cipher) for cipher in CipherSuite}

    def test_roundtrip_each_cipher(self):
        for cipher, blob in self.sealed.items():
            with self.subTest(cipher=cipher.name):
                self.assertIsInstance(blob, bytes)
                self.assertEqual(blob[:6], b"LSEC\x01\x00")
                self.assertEqual(blob[6], int(cipher))
                self.assertNotIn(PLAINTEXT, blob)
                with vault.unseal(blob, PASSPHRASE) as plain:
                    self.assertIsInstance(plain, SecureBuffer)
                    self.assertEqual(plain.to_bytes(), PLAINTEXT)

    def test_default_cipher_is_chacha(self):
        blob = vault.seal(b"x", b"p")
        self.assertEqual(blob[6], CipherSuite.CHACHA20_POLY1305)

    def test_wrong_passphrase(self):
        with self.assertRaises(lsec.CryptoError) as ctx:
            vault.unseal(self.sealed[CipherSuite.CHACHA20_POLY1305], b"wrong")
        self.assertEqual(ctx.exception.code, -6)

    def test_tampered_ciphertext(self):
        blob = bytearray(self.sealed[CipherSuite.AES256_GCM])
        blob[-1] ^= 0x01
        with self.assertRaises(lsec.CryptoError):
            vault.unseal(blob, PASSPHRASE)

    def test_tampered_salt(self):
        blob = bytearray(self.sealed[CipherSuite.CHACHA20_POLY1305])
        blob[8] ^= 0x01
        with self.assertRaises(lsec.CryptoError):
            vault.unseal(blob, PASSPHRASE)

    def test_bad_magic(self):
        blob = bytearray(self.sealed[CipherSuite.CHACHA20_POLY1305])
        blob[0] = ord("X")
        with self.assertRaises(lsec.VaultCorruptError) as ctx:
            vault.unseal(blob, PASSPHRASE)
        self.assertEqual(ctx.exception.code, -7)

    def test_truncated_header(self):
        with self.assertRaises(lsec.VaultCorruptError):
            vault.unseal(self.sealed[CipherSuite.CHACHA20_POLY1305][: HEADER_SIZE - 1], PASSPHRASE)

    def test_empty_vault(self):
        with self.assertRaises(lsec.VaultCorruptError):
            vault.unseal(b"", PASSPHRASE)

    def test_unknown_cipher_in_header(self):
        blob = bytearray(self.sealed[CipherSuite.CHACHA20_POLY1305])
        blob[6] = 9
        with self.assertRaises(lsec.InvalidParameterError):
            vault.unseal(blob, PASSPHRASE)

    def test_unknown_cipher_on_seal(self):
        with self.assertRaises(lsec.InvalidParameterError) as ctx:
            vault.seal(b"x", b"p", 9)
        self.assertEqual(ctx.exception.code, -3)
        with self.assertRaises(lsec.InvalidParameterError):
            vault.seal(b"x", b"p", 300)

    def test_secure_buffer_inputs(self):
        with SecureBuffer.from_bytes(PLAINTEXT) as plain, SecureBuffer.from_bytes(PASSPHRASE) as pw:
            blob = vault.seal(plain, pw, CipherSuite.AES256_GCM)
            with vault.unseal(blob, pw) as out:
                self.assertEqual(out.to_bytes(), PLAINTEXT)

    def test_str_inputs(self):
        secret = "unicode ✓ secret"
        passphrase = "pässwörd"
        blob = vault.seal(secret, passphrase)
        with vault.unseal(blob, passphrase) as out:
            self.assertEqual(out.to_bytes(), secret.encode("utf-8"))

    def test_empty_plaintext(self):
        blob = vault.seal(b"", PASSPHRASE)
        with vault.unseal(blob, PASSPHRASE) as out:
            self.assertEqual(len(out), 0)


@requires_lib
class VaultFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lsec-py-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_file_roundtrip(self):
        path = os.path.join(self.tmp, "creds.vault")
        vault.seal_to_file(path, PLAINTEXT, PASSPHRASE, CipherSuite.AES256_GCM)
        self.assertTrue(os.path.isfile(path))
        with vault.unseal_from_file(path, PASSPHRASE) as out:
            self.assertEqual(out.to_bytes(), PLAINTEXT)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(6), b"LSEC\x01\x00")

    def test_pathlike(self):
        path = Path(self.tmp) / "p.vault"
        vault.seal_to_file(path, b"x", b"p")
        with vault.unseal_from_file(path, b"p") as out:
            self.assertEqual(out.to_bytes(), b"x")

    def test_missing_file(self):
        with self.assertRaises(lsec.VaultIOError) as ctx:
            vault.unseal_from_file(os.path.join(self.tmp, "nope.vault"), PASSPHRASE)
        self.assertIsInstance(ctx.exception, OSError)
        self.assertEqual(ctx.exception.code, -8)

    def test_nul_in_path_rejected(self):
        target = os.path.join(self.tmp, "secrets.vault")
        with self.assertRaises(lsec.InvalidParameterError):
            vault.seal_to_file(target + "\x00.bak", b"x", b"p")
        self.assertFalse(os.path.exists(target))
        with self.assertRaises(lsec.InvalidParameterError):
            vault.unseal_from_file(target + "\x00", b"p")

    def test_wrong_passphrase_from_file(self):
        path = os.path.join(self.tmp, "w.vault")
        vault.seal_to_file(path, b"x", b"right")
        with self.assertRaises(lsec.CryptoError):
            vault.unseal_from_file(path, b"wrong")


if __name__ == "__main__":
    unittest.main()
