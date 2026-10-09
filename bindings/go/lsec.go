package lsec

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/lsec-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -llsec_ffi -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/release
#include "lsec.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type CipherSuite uint8

const (
	CipherChaCha20Poly1305 CipherSuite = C.LSEC_CIPHER_CHACHA20_POLY1305
	CipherAES256GCM        CipherSuite = C.LSEC_CIPHER_AES256_GCM
)

type TotpAlgorithm uint8

const (
	TotpSha1   TotpAlgorithm = C.LSEC_TOTP_ALGO_SHA1
	TotpSha256 TotpAlgorithm = C.LSEC_TOTP_ALGO_SHA256
	TotpSha512 TotpAlgorithm = C.LSEC_TOTP_ALGO_SHA512
)

var (
	ErrNullPointer    = errors.New("lsec: null pointer passed to c-abi")
	ErrBufferTooSmall = errors.New("lsec: destination buffer too small")
	ErrInvalidParam   = errors.New("lsec: invalid parameter")
	ErrAllocFailed    = errors.New("lsec: memory allocation failed")
	ErrLockFailed     = errors.New("lsec: failed to lock memory pages into physical ram")
	ErrCryptoFailed   = errors.New("lsec: cryptographic operation failed")
	ErrVaultCorrupt   = errors.New("lsec: vault payload is corrupted or header is invalid")
	ErrIOFailed       = errors.New("lsec: filesystem io operation failed")
	ErrTotpFailed     = errors.New("lsec: totp calculation or verification failed")
	ErrPanic          = errors.New("lsec: unexpected panic caught across ffi boundary")
	ErrUnknown        = errors.New("lsec: unknown internal error")
)

func mapStatus(status C.int32_t) error {
	switch status {
	case C.LSEC_OK:
		return nil
	case C.LSEC_ERR_NULL_POINTER:
		return ErrNullPointer
	case C.LSEC_ERR_BUFFER_TOO_SMALL:
		return ErrBufferTooSmall
	case C.LSEC_ERR_INVALID_PARAM:
		return ErrInvalidParam
	case C.LSEC_ERR_ALLOC_FAILED:
		return ErrAllocFailed
	case C.LSEC_ERR_LOCK_FAILED:
		return ErrLockFailed
	case C.LSEC_ERR_CRYPTO_FAILED:
		return ErrCryptoFailed
	case C.LSEC_ERR_VAULT_CORRUPT:
		return ErrVaultCorrupt
	case C.LSEC_ERR_IO_FAILED:
		return ErrIOFailed
	case C.LSEC_ERR_TOTP_FAILED:
		return ErrTotpFailed
	case C.LSEC_ERR_PANIC:
		return ErrPanic
	default:
		return ErrUnknown
	}
}

type Buffer struct {
	ptr *C.lsec_protected_buffer_t
}

func newBufferFromHandle(handle *C.lsec_protected_buffer_t) *Buffer {
	if handle == nil {
		return nil
	}
	buf := &Buffer{ptr: handle}
	runtime.SetFinalizer(buf, func(b *Buffer) {
		b.Free()
	})
	return buf
}

func NewBuffer(data []byte) (*Buffer, error) {
	var handle *C.lsec_protected_buffer_t
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}

	status := C.lsec_buffer_new(dataPtr, C.size_t(len(data)), &handle)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return newBufferFromHandle(handle), nil
}

func NewZeroedBuffer(length int) (*Buffer, error) {
	if length < 0 {
		return nil, ErrInvalidParam
	}

	var handle *C.lsec_protected_buffer_t
	status := C.lsec_buffer_zeroed(C.size_t(length), &handle)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return newBufferFromHandle(handle), nil
}

func (b *Buffer) Len() int {
	if b == nil || b.ptr == nil {
		return 0
	}
	defer runtime.KeepAlive(b)
	return int(C.lsec_buffer_len(b.ptr))
}

func (b *Buffer) Bytes() []byte {
	if b == nil || b.ptr == nil {
		return nil
	}
	defer runtime.KeepAlive(b)
	length := b.Len()
	if length == 0 {
		return []byte{}
	}
	raw := C.lsec_buffer_data(b.ptr)
	if raw == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(raw), C.int(length))
}

func (b *Buffer) Wipe() error {
	if b == nil || b.ptr == nil {
		return nil
	}
	defer runtime.KeepAlive(b)
	return mapStatus(C.lsec_buffer_wipe(b.ptr))
}

func (b *Buffer) Free() {
	if b != nil && b.ptr != nil {
		runtime.SetFinalizer(b, nil)
		C.lsec_buffer_free(b.ptr)
		b.ptr = nil
	}
}

func Version() (major, minor, patch uint32) {
	major = uint32(C.lsec_version_major())
	minor = uint32(C.lsec_version_minor())
	patch = uint32(C.lsec_version_patch())
	return
}

func Seal(plaintext, passphrase []byte, cipher CipherSuite) ([]byte, error) {
	var plainPtr, passPtr *C.uint8_t
	if len(plaintext) > 0 {
		plainPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}
	if len(passphrase) > 0 {
		passPtr = (*C.uint8_t)(unsafe.Pointer(&passphrase[0]))
	}

	var outBytes *C.uint8_t
	var outLen C.size_t

	status := C.lsec_vault_seal(
		plainPtr, C.size_t(len(plaintext)),
		passPtr, C.size_t(len(passphrase)),
		C.uint8_t(cipher),
		&outBytes, &outLen,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}
	defer C.lsec_vault_bytes_free(outBytes, outLen)

	return C.GoBytes(unsafe.Pointer(outBytes), C.int(outLen)), nil
}

func Unseal(vaultBytes, passphrase []byte) (*Buffer, error) {
	if len(vaultBytes) == 0 {
		return nil, ErrVaultCorrupt
	}
	vaultPtr := (*C.uint8_t)(unsafe.Pointer(&vaultBytes[0]))

	var passPtr *C.uint8_t
	if len(passphrase) > 0 {
		passPtr = (*C.uint8_t)(unsafe.Pointer(&passphrase[0]))
	}

	var outHandle *C.lsec_protected_buffer_t
	status := C.lsec_vault_unseal(
		vaultPtr, C.size_t(len(vaultBytes)),
		passPtr, C.size_t(len(passphrase)),
		&outHandle,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return newBufferFromHandle(outHandle), nil
}

func SealToFile(path string, plaintext, passphrase []byte, cipher CipherSuite) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var plainPtr, passPtr *C.uint8_t
	if len(plaintext) > 0 {
		plainPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}
	if len(passphrase) > 0 {
		passPtr = (*C.uint8_t)(unsafe.Pointer(&passphrase[0]))
	}

	status := C.lsec_vault_seal_to_file(
		cPath,
		plainPtr, C.size_t(len(plaintext)),
		passPtr, C.size_t(len(passphrase)),
		C.uint8_t(cipher),
	)
	return mapStatus(status)
}

func UnsealFromFile(path string, passphrase []byte) (*Buffer, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var passPtr *C.uint8_t
	if len(passphrase) > 0 {
		passPtr = (*C.uint8_t)(unsafe.Pointer(&passphrase[0]))
	}

	var outHandle *C.lsec_protected_buffer_t
	status := C.lsec_vault_unseal_from_file(
		cPath,
		passPtr, C.size_t(len(passphrase)),
		&outHandle,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return newBufferFromHandle(outHandle), nil
}

func DecodeBase32(base32Secret string) (*Buffer, error) {
	cSecret := C.CString(base32Secret)
	defer C.free(unsafe.Pointer(cSecret))

	var outHandle *C.lsec_protected_buffer_t
	status := C.lsec_totp_decode_base32(cSecret, &outHandle)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return newBufferFromHandle(outHandle), nil
}

func GenerateTOTP(secret []byte, timestamp uint64, stepSeconds uint64, digits uint32, algo TotpAlgorithm) (string, error) {
	if len(secret) == 0 {
		return "", ErrInvalidParam
	}
	secPtr := (*C.uint8_t)(unsafe.Pointer(&secret[0]))

	buf := make([]byte, digits+1)
	status := C.lsec_totp_generate(
		secPtr, C.size_t(len(secret)),
		C.uint64_t(timestamp),
		C.uint64_t(stepSeconds),
		C.uint32_t(digits),
		C.uint8_t(algo),
		(*C.char)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
	)
	if err := mapStatus(status); err != nil {
		return "", err
	}

	return string(buf[:digits]), nil
}

func VerifyTOTP(secret []byte, code string, timestamp uint64, stepSeconds uint64, digits uint32, driftSteps uint8, algo TotpAlgorithm) (bool, error) {
	if len(secret) == 0 {
		return false, ErrInvalidParam
	}
	secPtr := (*C.uint8_t)(unsafe.Pointer(&secret[0]))

	cCode := C.CString(code)
	defer C.free(unsafe.Pointer(cCode))

	var isValid C.int32_t
	status := C.lsec_totp_verify(
		secPtr, C.size_t(len(secret)),
		cCode,
		C.uint64_t(timestamp),
		C.uint64_t(stepSeconds),
		C.uint32_t(digits),
		C.uint8_t(driftSteps),
		C.uint8_t(algo),
		&isValid,
	)
	if err := mapStatus(status); err != nil {
		return false, err
	}

	return isValid == 1, nil
}
