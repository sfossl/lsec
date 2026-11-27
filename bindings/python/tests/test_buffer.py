import ctypes
import gc
import pickle
import threading
import unittest

from tests._support import lsec, requires_lib
from lsec import SecureBuffer
from lsec.buffer import _borrow


@requires_lib
class SecureBufferTests(unittest.TestCase):
    def test_from_bytes_roundtrip(self):
        with SecureBuffer.from_bytes(b"top-secret") as buf:
            self.assertEqual(len(buf), 10)
            self.assertEqual(buf.to_bytes(), b"top-secret")

    def test_accepts_str_bytearray_memoryview(self):
        for data in ("top-secret", bytearray(b"top-secret"), memoryview(b"top-secret")):
            with self.subTest(type=type(data).__name__):
                with SecureBuffer.from_bytes(data) as buf:
                    self.assertEqual(buf.to_bytes(), b"top-secret")

    def test_rejects_unsupported_types(self):
        with self.assertRaises(TypeError):
            SecureBuffer.from_bytes(12345)

    def test_wipe_source_zeroes_bytearray(self):
        source = bytearray(b"wipe-me-please")
        with SecureBuffer.from_bytes(source, wipe_source=True) as buf:
            self.assertEqual(buf.to_bytes(), b"wipe-me-please")
        self.assertEqual(source, bytearray(len(source)))

    def test_source_kept_by_default(self):
        source = bytearray(b"keep-me")
        SecureBuffer.from_bytes(source).free()
        self.assertEqual(source, bytearray(b"keep-me"))

    def test_zeroed(self):
        with SecureBuffer.zeroed(32) as buf:
            self.assertEqual(buf.to_bytes(), bytes(32))

    def test_zeroed_rejects_bad_lengths(self):
        for bad in (-1, True, 2.0, "4"):
            with self.subTest(bad=bad):
                with self.assertRaises(lsec.InvalidParameterError):
                    SecureBuffer.zeroed(bad)

    def test_empty_buffer(self):
        with SecureBuffer.from_bytes(b"") as buf:
            self.assertEqual(len(buf), 0)
            self.assertEqual(buf.to_bytes(), b"")
            self.assertEqual(bytes(buf.view()), b"")
            buf.wipe()

    def test_over_max_locked_size_raises_allocation_error(self):
        with self.assertRaises(lsec.AllocationError) as ctx:
            SecureBuffer.zeroed(16 * 1024 * 1024 + 1)
        self.assertEqual(ctx.exception.code, -4)

    def test_wipe_zeroes_in_place(self):
        with SecureBuffer.from_bytes(b"sensitive") as buf:
            view = buf.view()
            self.assertEqual(bytes(view), b"sensitive")
            buf.wipe()
            self.assertEqual(bytes(view), bytes(9))
            self.assertEqual(len(buf), 9)

    def test_view_is_writable_and_zero_copy(self):
        with SecureBuffer.zeroed(4) as buf:
            view = buf.view()
            view[:] = b"abcd"
            self.assertEqual(buf.to_bytes(), b"abcd")

    def test_write_with_offset(self):
        with SecureBuffer.zeroed(8) as buf:
            buf.write(b"key", offset=2)
            self.assertEqual(buf.to_bytes(), b"\x00\x00key\x00\x00\x00")

    def test_write_out_of_bounds(self):
        with SecureBuffer.zeroed(4) as buf:
            with self.assertRaises(lsec.InvalidParameterError):
                buf.write(b"12345")
            with self.assertRaises(lsec.InvalidParameterError):
                buf.write(b"12", offset=3)
            with self.assertRaises(lsec.InvalidParameterError):
                buf.write(b"1", offset=-1)

    def test_buffer_as_input_to_another_buffer(self):
        with SecureBuffer.from_bytes(b"nested") as src, SecureBuffer.from_bytes(src) as dst:
            self.assertEqual(dst.to_bytes(), b"nested")

    def test_context_manager_frees(self):
        with SecureBuffer.from_bytes(b"x") as buf:
            pass
        self.assertTrue(buf.closed)

    def test_use_after_free_raises(self):
        buf = SecureBuffer.from_bytes(b"x")
        buf.free()
        for action in (buf.to_bytes, buf.wipe, buf.view, lambda: len(buf), lambda: buf.write(b"")):
            with self.assertRaises(ValueError):
                action()

    def test_free_is_idempotent(self):
        buf = SecureBuffer.from_bytes(b"x")
        buf.free()
        buf.free()

    def test_free_without_views_releases_immediately(self):
        buf = SecureBuffer.from_bytes(b"x")
        with buf.view():
            pass
        buf.free()
        self.assertIsNone(buf._pending_free)

    def test_free_with_live_slice_wipes_then_defers(self):
        buf = SecureBuffer.from_bytes(b"dangling?")
        view = buf.view()
        head = view[:4]
        del view
        buf.free()
        self.assertTrue(buf.closed)
        # the slice still points at allocated (wiped) memory, not freed memory
        self.assertEqual(bytes(head), bytes(4))
        self.assertTrue(buf._pending_free.alive)
        del head
        gc.collect()
        self.assertFalse(buf._pending_free.alive)

    def test_free_with_nested_export_defers(self):
        buf = SecureBuffer.from_bytes(b"exported")
        view = buf.view()
        exported = (ctypes.c_uint8 * 8).from_buffer(view)
        del view
        buf.free()
        self.assertEqual(bytes(exported), bytes(8))
        self.assertTrue(buf._pending_free.alive)
        del exported
        gc.collect()
        self.assertFalse(buf._pending_free.alive)

    def test_views_share_one_array(self):
        with SecureBuffer.from_bytes(b"abc") as buf:
            first = buf.view()
            for _ in range(100):
                buf.view().release()
            self.assertIs(buf._array_ref(), buf._array_ref())
            self.assertEqual(bytes(first), b"abc")
            first.release()

    def test_free_waits_for_in_flight_native_use(self):
        buf = SecureBuffer.from_bytes(b"in-use")
        borrowed = threading.Event()
        release = threading.Event()
        freed = threading.Event()

        def hold():
            with _borrow(buf):
                borrowed.set()
                release.wait(5)

        def free():
            buf.free()
            freed.set()

        holder = threading.Thread(target=hold)
        holder.start()
        self.assertTrue(borrowed.wait(5))
        freer = threading.Thread(target=free)
        freer.start()
        self.assertFalse(freed.wait(0.2), "free() must block while the buffer is borrowed")
        with self.assertRaises(ValueError):
            buf.to_bytes()  # new uses are refused once freeing has started
        release.set()
        holder.join(5)
        freer.join(5)
        self.assertTrue(freed.is_set())

    def test_repr_hides_contents(self):
        with SecureBuffer.from_bytes(b"hunter2") as buf:
            self.assertNotIn("hunter2", repr(buf))
            self.assertIn("len=7", repr(buf))
        self.assertIn("freed", repr(buf))

    def test_not_picklable(self):
        with SecureBuffer.from_bytes(b"x") as buf:
            with self.assertRaises(TypeError):
                pickle.dumps(buf)


if __name__ == "__main__":
    unittest.main()
