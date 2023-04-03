package main

/*
#cgo CFLAGS: -g -Wall -I./libomemo-c/src
#cgo LDFLAGS: -L./libomemo-c/build/src -lomemo-c -lm
#include <stdlib.h>
#include "signal_protocol.h"
#include "signal_protocol_types.h"

/// SIGNAL CRYPTO PROVIDER ///

typedef int (*signal_encrypt_func)(signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *plaintext, size_t plaintext_len,
	void *user_data);

int call_go_encrypt(signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *plaintext, size_t plaintext_len,
	void *user_data);

typedef int (*signal_decrypt_func)(signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *ciphertext, size_t ciphertext_len,
	void *user_data);

int call_go_decrypt(
	signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *ciphertext, size_t ciphertext_len,
	void *user_data);

typedef int (*signal_hmac_sha256_init_func)(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
int call_go_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);

typedef int (*signal_hmac_sha256_update_func)(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
int call_go_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);

typedef int (*signal_hmac_sha256_final_func)(void *hmac_context, signal_buffer **output, void *user_data);
int call_go_hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data);

typedef void (*signal_hmac_sha256_cleanup_func)(void *hmac_context, void *user_data);
void call_hmac_sha256_cleanup(void *hmac_context, void *user_data);

typedef int (*signal_sha512_digest_init_func)(void **digest_context, void *user_data);
typedef int (*signal_sha512_digest_update_func)(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
typedef int (*signal_sha512_digest_final_func)(void *digest_context, signal_buffer **output, void *user_data);
typedef void (*signal_sha512_digest_cleanup_func)(void *digest_context, void *user_data);

/// SIGNAL LOCKING FUNCTIONS ///

typedef void (*signal_lock_func)(void*);
void call_go_lock(void *user_data);

typedef void (*signal_unlock_func)(void*);
void call_go_unlock(void *user_data);
*/
import "C"
import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"runtime/cgo"
	"sync"
	"unsafe"
)

//export goEncrypt
func goEncrypt(
	output **C.signal_buffer,
	cipher C.int,
	key *C.uint8_t, keyLen C.size_t,
	iv *C.uint8_t, ivLen C.size_t,
	plaintext *C.uint8_t, plaintextLen C.size_t,
	userData unsafe.Pointer) C.int {
	return C.int(-1) // TODO
}

//export goDecrypt
func goDecrypt(
	output **C.signal_buffer,
	cipher C.int,
	key *C.uint8_t, keyLen C.size_t,
	iv *C.uint8_t, ivLen C.size_t,
	plaintext *C.uint8_t, plaintextLen C.size_t,
	userData unsafe.Pointer) C.int {
	return C.int(-1) // TODO
}

var globalContextMutex sync.Mutex

//export goLock
func goLock(userData unsafe.Pointer) {
	// TODO: Could save a mutex in the user data.
	globalContextMutex.Lock()
}

//export goUnlock
func goUnlock(userData unsafe.Pointer) {
	// TODO: Could save a mutex in the user data.
	globalContextMutex.Unlock()
}

//export goHmacSha256Init
func goHmacSha256Init(hmacContext *unsafe.Pointer, key *C.uint8_t, keyLen C.size_t, userData unsafe.Pointer) C.int {
	mac := hmacSha256New(
		C.GoBytes(unsafe.Pointer(key), C.int(keyLen)),
	)

	hmacHandle := cgo.NewHandle(mac)
	*hmacContext = unsafe.Pointer(&hmacHandle)

	return C.int(0)
}

// hmacSha256New create a new HMAC SHA256 writer.
func hmacSha256New(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

//export goHmacSha256Update
func goHmacSha256Update(hmacContext unsafe.Pointer, data *C.uint8_t, dataLen C.size_t, userData unsafe.Pointer) C.int {
	hmacHandle := *(*cgo.Handle)(hmacContext)
	hmacSha265Write(
		hmacHandle.Value().(hash.Hash),
		C.GoBytes(unsafe.Pointer(data), C.int(dataLen)),
	)

	return C.int(0)
}

// hmacSha265Write writes the given data to the mac object.
func hmacSha265Write(mac hash.Hash, data []byte) {
	mac.Write(data)
}

//export goHmacSha256Final
func goHmacSha256Final(hmacContext unsafe.Pointer, output **C.signal_buffer, userData unsafe.Pointer) C.int {
	hmacHandle := *(*cgo.Handle)(hmacContext)
	hmacSum := hmacSha256Sum(
		hmacHandle.Value().(hash.Hash),
	)

	*output = C.signal_buffer_create(
		(*C.uchar)(&hmacSum[0]),
		C.ulong(len(hmacSum)),
	)

	return C.int(0)
}

func hmacSha256Sum(mac hash.Hash) []byte {
	return mac.Sum(nil)
}

//export goHmacSha256Cleanup
func goHmacSha256Cleanup(hmacContext unsafe.Pointer, userData unsafe.Pointer) {
	hmacHandle := *(*cgo.Handle)(hmacContext)
	hmacHandle.Delete()
}

func main() {
	var globalContext *C.signal_context

	userDataHandle := cgo.NewHandle(nil)
	var userData = unsafe.Pointer(&userDataHandle) // TODO: Should it really be a zero pointer?

	// TODO: Implement all the provider callbacks.
	provider := C.signal_crypto_provider{
		encrypt_func: (C.signal_encrypt_func)(unsafe.Pointer(C.call_go_encrypt)),
		decrypt_func: (C.signal_decrypt_func)(unsafe.Pointer(C.call_go_decrypt)),

		hmac_sha256_init_func:    (C.signal_hmac_sha256_init_func)(unsafe.Pointer(C.call_go_hmac_sha256_init)),
		hmac_sha256_update_func:  (C.signal_hmac_sha256_update_func)(unsafe.Pointer(C.call_go_hmac_sha256_update)),
		hmac_sha256_final_func:   (C.signal_hmac_sha256_final_func)(unsafe.Pointer(C.call_go_hmac_sha256_final)),
		hmac_sha256_cleanup_func: (C.signal_hmac_sha256_cleanup_func)(unsafe.Pointer(C.call_hmac_sha256_cleanup)),
	}

	lockFunction := (C.signal_lock_func)(unsafe.Pointer(C.call_go_lock))
	unlockFunction := (C.signal_unlock_func)(unsafe.Pointer(C.call_go_unlock))

	C.signal_context_create(&globalContext, userData)
	if cr := C.signal_context_set_crypto_provider(globalContext, &provider); cr < 0 {
		fmt.Println("could not set crypto provider:", cr)
	}
	if cr := C.signal_context_set_locking_functions(globalContext, lockFunction, unlockFunction); cr < 0 {
		fmt.Println("could not set locking functions:", cr)
	}

	fmt.Println(globalContext)
}
