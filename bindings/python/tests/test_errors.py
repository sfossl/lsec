import unittest

from tests._support import lsec
from lsec import errors


class ErrorMappingTests(unittest.TestCase):
    EXPECTED = {
        -1: errors.NullPointerError,
        -2: errors.BufferTooSmallError,
        -3: errors.InvalidParameterError,
        -4: errors.AllocationError,
        -5: errors.MemoryLockError,
        -6: errors.CryptoError,
        -7: errors.VaultCorruptError,
        -8: errors.VaultIOError,
        -9: errors.TotpError,
        -10: errors.PanicError,
    }

    def test_ok_does_not_raise(self):
        self.assertIsNone(errors.check(0))

    def test_every_code_maps_to_its_exception(self):
        for code, cls in self.EXPECTED.items():
            with self.subTest(code=code):
                with self.assertRaises(cls) as ctx:
                    errors.check(code)
                self.assertEqual(ctx.exception.code, code)
                self.assertIsInstance(ctx.exception, lsec.LsecError)
                self.assertTrue(str(ctx.exception).startswith("lsec: "))

    def test_codes_match_header(self):
        header_codes = {
            "LSEC_ERR_NULL_POINTER": -1,
            "LSEC_ERR_BUFFER_TOO_SMALL": -2,
            "LSEC_ERR_INVALID_PARAM": -3,
            "LSEC_ERR_ALLOC_FAILED": -4,
            "LSEC_ERR_LOCK_FAILED": -5,
            "LSEC_ERR_CRYPTO_FAILED": -6,
            "LSEC_ERR_VAULT_CORRUPT": -7,
            "LSEC_ERR_IO_FAILED": -8,
            "LSEC_ERR_TOTP_FAILED": -9,
            "LSEC_ERR_PANIC": -10,
        }
        for name, value in header_codes.items():
            self.assertEqual(getattr(errors, name), value)

    def test_unknown_code(self):
        with self.assertRaises(errors.UnknownError) as ctx:
            errors.check(-99)
        self.assertEqual(ctx.exception.code, -99)
        self.assertIn("-99", str(ctx.exception))

    def test_builtin_bases(self):
        self.assertTrue(issubclass(errors.InvalidParameterError, ValueError))
        self.assertTrue(issubclass(errors.AllocationError, MemoryError))
        self.assertTrue(issubclass(errors.VaultIOError, OSError))
        self.assertTrue(issubclass(errors.LibraryNotFoundError, OSError))

    def test_library_not_found_lists_paths(self):
        exc = errors.LibraryNotFoundError(tried=["/a/liblsec_ffi.so (missing)", "/b"])
        self.assertEqual(exc.tried, ["/a/liblsec_ffi.so (missing)", "/b"])
        self.assertIn("/a/liblsec_ffi.so", str(exc))
        self.assertIn("LSEC_LIB_PATH", str(exc))


if __name__ == "__main__":
    unittest.main()
