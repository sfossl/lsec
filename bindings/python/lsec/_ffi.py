from ctypes import CDLL, POINTER, Structure, c_char, c_char_p, c_int32, c_size_t, c_uint8, c_uint32, c_uint64

LSEC_CIPHER_CHACHA20_POLY1305 = 1
LSEC_CIPHER_AES256_GCM = 2

LSEC_TOTP_ALGO_SHA1 = 0
LSEC_TOTP_ALGO_SHA256 = 1
LSEC_TOTP_ALGO_SHA512 = 2


class LsecProtectedBuffer(Structure):
    """Opaque lsec_protected_buffer_t."""


BufferHandle = POINTER(LsecProtectedBuffer)
BytePtr = POINTER(c_uint8)

_SIGNATURES = {
    "lsec_version_major": (c_uint32, []),
    "lsec_version_minor": (c_uint32, []),
    "lsec_version_patch": (c_uint32, []),
    "lsec_buffer_new": (c_int32, [BytePtr, c_size_t, POINTER(BufferHandle)]),
    "lsec_buffer_zeroed": (c_int32, [c_size_t, POINTER(BufferHandle)]),
    "lsec_buffer_len": (c_size_t, [BufferHandle]),
    "lsec_buffer_data": (BytePtr, [BufferHandle]),
    "lsec_buffer_data_mut": (BytePtr, [BufferHandle]),
    "lsec_buffer_wipe": (c_int32, [BufferHandle]),
    "lsec_buffer_free": (None, [BufferHandle]),
    "lsec_vault_seal": (
        c_int32,
        [BytePtr, c_size_t, BytePtr, c_size_t, c_uint8, POINTER(BytePtr), POINTER(c_size_t)],
    ),
    "lsec_vault_unseal": (
        c_int32,
        [BytePtr, c_size_t, BytePtr, c_size_t, POINTER(BufferHandle)],
    ),
    "lsec_vault_seal_to_file": (
        c_int32,
        [c_char_p, BytePtr, c_size_t, BytePtr, c_size_t, c_uint8],
    ),
    "lsec_vault_unseal_from_file": (
        c_int32,
        [c_char_p, BytePtr, c_size_t, POINTER(BufferHandle)],
    ),
    "lsec_vault_bytes_free": (None, [BytePtr, c_size_t]),
    "lsec_totp_decode_base32": (c_int32, [c_char_p, POINTER(BufferHandle)]),
    "lsec_totp_generate": (
        c_int32,
        [BytePtr, c_size_t, c_uint64, c_uint64, c_uint32, c_uint8, POINTER(c_char), c_size_t],
    ),
    "lsec_totp_verify": (
        c_int32,
        [BytePtr, c_size_t, c_char_p, c_uint64, c_uint64, c_uint32, c_uint8, c_uint8, POINTER(c_int32)],
    ),
}


def declare_signatures(lib: CDLL) -> None:
    """Attach argtypes/restype for every export in lsec.h."""
    for name, (restype, argtypes) in _SIGNATURES.items():
        func = getattr(lib, name)
        func.restype = restype
        func.argtypes = argtypes
