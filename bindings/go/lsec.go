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
	"math"
	"runtime"
	"sync"
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

var emptyByte C.uint8_t

func slicePtr(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return &emptyByte, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

func takeVaultBytes(ptr *C.uint8_t, length C.size_t) ([]byte, error) {
	defer C.lsec_vault_bytes_free(ptr, length)
	if length > math.MaxInt32 {
		return nil, ErrAllocFailed
	}
	if length == 0 || ptr == nil {
		return []byte{}, nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}

type Buffer struct {
	mu  sync.Mutex
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
	dataPtr, dataLen := slicePtr(data)

	status := C.lsec_buffer_new(dataPtr, dataLen, &handle)
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
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ptr == nil {
		return 0
	}
	defer runtime.KeepAlive(b)
	return int(C.lsec_buffer_len(b.ptr))
}

func (b *Buffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ptr == nil {
		return nil
	}
	defer runtime.KeepAlive(b)
	length := int(C.lsec_buffer_len(b.ptr))
	if length == 0 {
		return []byte{}
	}
	raw := C.lsec_buffer_data(b.ptr)
	if raw == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(raw), C.int(length))
}

func (b *Buffer) Write(data []byte, offset int) error {
	if b == nil {
		return ErrNullPointer
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ptr == nil {
		return ErrNullPointer
	}
	defer runtime.KeepAlive(b)
	if offset < 0 {
		return ErrInvalidParam
	}
	length := int(C.lsec_buffer_len(b.ptr))
	if offset > length || len(data) > length-offset {
		return ErrBufferTooSmall
	}
	if len(data) == 0 {
		return nil
	}
	raw := C.lsec_buffer_data_mut(b.ptr)
	if raw == nil {
		return ErrNullPointer
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(raw)), length)
	copy(dst[offset:], data)
	return nil
}

func (b *Buffer) Wipe() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ptr == nil {
		return nil
	}
	defer runtime.KeepAlive(b)
	return mapStatus(C.lsec_buffer_wipe(b.ptr))
}

func (b *Buffer) Free() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ptr != nil {
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
	plainPtr, plainLen := slicePtr(plaintext)
	passPtr, passLen := slicePtr(passphrase)

	var outBytes *C.uint8_t
	var outLen C.size_t

	status := C.lsec_vault_seal(
		plainPtr, plainLen,
		passPtr, passLen,
		C.uint8_t(cipher),
		&outBytes, &outLen,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return takeVaultBytes(outBytes, outLen)
}

func Unseal(vaultBytes, passphrase []byte) (*Buffer, error) {
	if len(vaultBytes) == 0 {
		return nil, ErrVaultCorrupt
	}
	vaultPtr, vaultLen := slicePtr(vaultBytes)
	passPtr, passLen := slicePtr(passphrase)

	var outHandle *C.lsec_protected_buffer_t
	status := C.lsec_vault_unseal(
		vaultPtr, vaultLen,
		passPtr, passLen,
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

	plainPtr, plainLen := slicePtr(plaintext)
	passPtr, passLen := slicePtr(passphrase)

	status := C.lsec_vault_seal_to_file(
		cPath,
		plainPtr, plainLen,
		passPtr, passLen,
		C.uint8_t(cipher),
	)
	return mapStatus(status)
}

func UnsealFromFile(path string, passphrase []byte) (*Buffer, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	passPtr, passLen := slicePtr(passphrase)

	var outHandle *C.lsec_protected_buffer_t
	status := C.lsec_vault_unseal_from_file(
		cPath,
		passPtr, passLen,
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

func ProcessHarden() error {
	status := C.lsec_process_harden()
	return mapStatus(status)
}

func MultiVaultCreate(payload, passphrase []byte, cipher CipherSuite) ([]byte, error) {
	plainPtr, plainLen := slicePtr(payload)
	passPtr, passLen := slicePtr(passphrase)

	var outBytes *C.uint8_t
	var outLen C.size_t

	status := C.lsec_multi_vault_create(
		plainPtr, plainLen,
		passPtr, passLen,
		C.uint8_t(cipher),
		&outBytes, &outLen,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return takeVaultBytes(outBytes, outLen)
}

func MultiVaultOpen(container, passphrase []byte) (*Buffer, error) {
	contPtr, contLen := slicePtr(container)
	passPtr, passLen := slicePtr(passphrase)

	var outBuf *C.lsec_protected_buffer_t
	status := C.lsec_multi_vault_open(contPtr, contLen, passPtr, passLen, &outBuf)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	b := &Buffer{ptr: outBuf}
	runtime.SetFinalizer(b, (*Buffer).Free)
	return b, nil
}

func MultiVaultAddSlot(container []byte, existingPassphrase, newPassphrase []byte, cipher CipherSuite) (int, error) {
	if len(container) == 0 {
		return -1, ErrVaultCorrupt
	}
	cPtr, cLen := slicePtr(container)
	existPtr, existLen := slicePtr(existingPassphrase)
	newPtr, newLen := slicePtr(newPassphrase)

	var slotIndex C.size_t
	status := C.lsec_multi_vault_add_slot(
		cPtr, cLen,
		existPtr, existLen,
		newPtr, newLen,
		C.uint8_t(cipher),
		&slotIndex,
	)
	if err := mapStatus(status); err != nil {
		return -1, err
	}

	return int(slotIndex), nil
}

func MultiVaultRemoveSlot(container []byte, existingPassphrase []byte, slotIndex int) error {
	if slotIndex < 0 {
		return ErrInvalidParam
	}
	if len(container) == 0 {
		return ErrVaultCorrupt
	}
	cPtr, cLen := slicePtr(container)
	existPtr, existLen := slicePtr(existingPassphrase)

	status := C.lsec_multi_vault_remove_slot(
		cPtr, cLen,
		existPtr, existLen,
		C.size_t(slotIndex),
	)
	return mapStatus(status)
}

func MultiVaultUpdatePayload(container []byte, existingPassphrase, newPayload []byte) ([]byte, error) {
	if len(container) == 0 {
		return nil, ErrVaultCorrupt
	}
	cPtr, cLen := slicePtr(container)
	existPtr, existLen := slicePtr(existingPassphrase)
	plainPtr, plainLen := slicePtr(newPayload)

	var outBytes *C.uint8_t
	var outLen C.size_t

	status := C.lsec_multi_vault_update_payload(
		cPtr, cLen,
		existPtr, existLen,
		plainPtr, plainLen,
		&outBytes, &outLen,
	)
	if err := mapStatus(status); err != nil {
		return nil, err
	}

	return takeVaultBytes(outBytes, outLen)
}

func MultiVaultActiveSlots(container []byte) ([4]bool, error) {
	var result [4]bool
	if len(container) == 0 {
		return result, ErrVaultCorrupt
	}
	cPtr, cLen := slicePtr(container)

	var slots [4]C.uint8_t
	status := C.lsec_multi_vault_active_slots(
		cPtr, cLen,
		(*C.uint8_t)(unsafe.Pointer(&slots[0])),
		4,
	)
	if err := mapStatus(status); err != nil {
		return result, err
	}

	for i := 0; i < 4; i++ {
		result[i] = slots[i] == 1
	}
	return result, nil
}
