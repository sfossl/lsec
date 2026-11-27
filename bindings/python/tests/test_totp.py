import time
import unittest

from tests._support import lsec, requires_lib
from lsec import SecureBuffer, Totp, TotpAlgorithm, totp

SEED_SHA1 = b"12345678901234567890"
SEED_SHA256 = b"12345678901234567890123456789012"
SEED_SHA512 = b"1234567890" * 6 + b"1234"

# RFC 6238 appendix B, 8 digits: (timestamp, sha1, sha256, sha512)
RFC_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@requires_lib
class Base32Tests(unittest.TestCase):
    def test_decode_standard_seed(self):
        with totp.decode_base32("JBSWY3DPEHPK3PXP") as seed:
            self.assertIsInstance(seed, SecureBuffer)
            self.assertEqual(seed.to_bytes(), b"Hello!\xde\xad\xbe\xef")

    def test_decode_ignores_case_spaces_hyphens_padding(self):
        with totp.decode_base32("jbsw-y3dp ee======") as seed:
            self.assertEqual(seed.to_bytes(), b"Hello!")

    def test_decode_bytes_input(self):
        with totp.decode_base32(b"JBSWY3DPEE") as seed:
            self.assertEqual(seed.to_bytes(), b"Hello!")

    def test_invalid_characters(self):
        for bad in ("JBSWY3DPE8", "JBSWY3DPE0", "!!!!"):
            with self.subTest(bad=bad):
                with self.assertRaises(lsec.TotpError) as ctx:
                    totp.decode_base32(bad)
                self.assertEqual(ctx.exception.code, -9)

    def test_nonzero_residual_bits(self):
        with self.assertRaises(lsec.TotpError):
            totp.decode_base32("JBSWY3DPEF======")

    def test_empty(self):
        with self.assertRaises(lsec.TotpError):
            totp.decode_base32("  --==")

    def test_embedded_nul_rejected(self):
        with self.assertRaises(lsec.InvalidParameterError):
            totp.decode_base32("JBSW\x00Y3DP")


@requires_lib
class GenerateTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for ts, sha1, sha256, sha512 in RFC_VECTORS:
            for seed, algo, expected in (
                (SEED_SHA1, TotpAlgorithm.SHA1, sha1),
                (SEED_SHA256, TotpAlgorithm.SHA256, sha256),
                (SEED_SHA512, TotpAlgorithm.SHA512, sha512),
            ):
                with self.subTest(ts=ts, algo=algo.name):
                    self.assertEqual(totp.generate(seed, timestamp=ts, digits=8, algorithm=algo), expected)

    def test_six_digit_default_is_suffix_of_eight(self):
        self.assertEqual(totp.generate(SEED_SHA1, timestamp=59), "287082")

    def test_secure_buffer_secret(self):
        with SecureBuffer.from_bytes(SEED_SHA1) as seed:
            self.assertEqual(totp.generate(seed, timestamp=59, digits=8), "94287082")

    def test_default_timestamp_is_now(self):
        now = int(time.time())
        code = totp.generate(SEED_SHA1)
        self.assertIn(code, {totp.generate(SEED_SHA1, timestamp=now + d) for d in (-30, 0, 30)})

    def test_invalid_digits(self):
        for digits in (5, 9, 65):
            with self.subTest(digits=digits):
                with self.assertRaises(lsec.TotpError):
                    totp.generate(SEED_SHA1, timestamp=59, digits=digits)

    def test_zero_step(self):
        with self.assertRaises(lsec.TotpError):
            totp.generate(SEED_SHA1, timestamp=59, step=0)

    def test_empty_secret(self):
        with self.assertRaises(lsec.TotpError):
            totp.generate(b"", timestamp=59)

    def test_unknown_algorithm(self):
        with self.assertRaises(lsec.InvalidParameterError) as ctx:
            totp.generate(SEED_SHA1, timestamp=59, algorithm=9)
        self.assertEqual(ctx.exception.code, -3)

    def test_argument_validation(self):
        with self.assertRaises(lsec.InvalidParameterError):
            totp.generate(SEED_SHA1, timestamp=-1)
        with self.assertRaises(lsec.InvalidParameterError):
            totp.generate(SEED_SHA1, timestamp=59, digits="6")


@requires_lib
class VerifyTests(unittest.TestCase):
    T = 1234567890

    def code_at(self, ts, **kw):
        return totp.generate(SEED_SHA1, timestamp=ts, **kw)

    def test_exact_step(self):
        self.assertTrue(totp.verify(SEED_SHA1, self.code_at(self.T), timestamp=self.T))

    def test_drift_one_step_each_side(self):
        for delta in (-30, 30):
            with self.subTest(delta=delta):
                code = self.code_at(self.T + delta)
                self.assertTrue(totp.verify(SEED_SHA1, code, timestamp=self.T, drift=1))
                self.assertFalse(totp.verify(SEED_SHA1, code, timestamp=self.T, drift=0))

    def test_outside_drift_window(self):
        code = self.code_at(self.T - 60)
        self.assertFalse(totp.verify(SEED_SHA1, code, timestamp=self.T, drift=1))
        self.assertTrue(totp.verify(SEED_SHA1, code, timestamp=self.T, drift=2))

    def test_wrong_code(self):
        self.assertFalse(totp.verify(SEED_SHA1, "000000", timestamp=self.T))

    def test_digits_not_inferred_from_code(self):
        code8 = self.code_at(self.T, digits=8)
        self.assertTrue(totp.verify(SEED_SHA1, code8, timestamp=self.T, digits=8))
        # a 6-digit guess must not downgrade an 8-digit check
        self.assertFalse(totp.verify(SEED_SHA1, code8[-6:], timestamp=self.T, digits=8))
        # and the default (6) does not accept an 8-digit code
        self.assertFalse(totp.verify(SEED_SHA1, code8, timestamp=self.T))

    def test_wrong_length_code_fails(self):
        self.assertFalse(totp.verify(SEED_SHA1, "12345", timestamp=self.T))

    def test_digits_validated_like_generate(self):
        for digits in (5, 9, 65):
            with self.subTest(digits=digits):
                with self.assertRaises(lsec.TotpError):
                    totp.verify(SEED_SHA1, "123456", timestamp=self.T, digits=digits)
        with self.assertRaises(lsec.InvalidParameterError):
            totp.verify(SEED_SHA1, "123456", timestamp=self.T, digits="6")

    def test_whitespace_trimmed(self):
        self.assertTrue(totp.verify(SEED_SHA1, f" {self.code_at(self.T)} ", timestamp=self.T))

    def test_algorithm_must_match(self):
        code = totp.generate(SEED_SHA256, timestamp=self.T, algorithm=TotpAlgorithm.SHA256)
        self.assertTrue(totp.verify(SEED_SHA256, code, timestamp=self.T, algorithm=TotpAlgorithm.SHA256))
        self.assertFalse(totp.verify(SEED_SHA256, code, timestamp=self.T, algorithm=TotpAlgorithm.SHA1))

    def test_errors(self):
        with self.assertRaises(lsec.TotpError):
            totp.verify(b"", "123456", timestamp=self.T)
        with self.assertRaises(lsec.TotpError):
            totp.verify(SEED_SHA1, "123456", timestamp=self.T, step=0)
        with self.assertRaises(lsec.InvalidParameterError):
            totp.verify(SEED_SHA1, "123456", timestamp=self.T, algorithm=7)
        with self.assertRaises(lsec.InvalidParameterError):
            totp.verify(SEED_SHA1, "123456", timestamp=self.T, drift=256)


@requires_lib
class TotpClassTests(unittest.TestCase):
    def test_base32_seed(self):
        with Totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits=8) as otp:
            self.assertEqual(otp.at(59), "94287082")
            self.assertTrue(otp.verify("94287082", timestamp=59))
            self.assertTrue(otp.verify(otp.now()))
            self.assertNotIn("GEZDG", repr(otp))

    def test_secure_buffer_seed_and_close(self):
        seed = SecureBuffer.from_bytes(SEED_SHA512)
        with Totp(seed, digits=8, algorithm=TotpAlgorithm.SHA512) as otp:
            self.assertEqual(otp.at(59), "90693936")
        self.assertTrue(seed.closed)

    def test_rejects_bad_secret_type(self):
        for bad in (123, b"GEZDGNBVGY3TQOJQ", bytearray(b"12345678901234567890")):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    Totp(bad)

    def test_rejects_invalid_digits(self):
        with self.assertRaises(lsec.TotpError):
            Totp("JBSWY3DPEHPK3PXP", digits=9)

    def test_invalid_step_raises_at_construction(self):
        with self.assertRaises(lsec.InvalidParameterError):
            Totp("JBSWY3DPEHPK3PXP", step=-1)


if __name__ == "__main__":
    unittest.main()
