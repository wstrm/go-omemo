package main

/*
#include "signal_protocol_types.h"

/// SIGNAL CRYPTO PROVIDER ///

int call_go_encrypt(
	signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *plaintext, size_t plaintext_len,
	void *user_data
) {
	int goEncrypt(signal_buffer**, int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, void*);
	return goEncrypt(output, cipher, key, key_len, iv, iv_len, plaintext, plaintext_len, user_data);
}

int call_go_decrypt(
	signal_buffer **output,
	int cipher,
	const uint8_t *key, size_t key_len,
	const uint8_t *iv, size_t iv_len,
	const uint8_t *ciphertext, size_t ciphertext_len,
	void *user_data
) {
	int goDecrypt(signal_buffer**, int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, void*);
	return goDecrypt(output, cipher, key, key_len, iv, iv_len, ciphertext, ciphertext_len, user_data);
}

int call_go_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data) {
	int goHmacSha256Init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
	return goHmacSha256Init(hmac_context, key, key_len, user_data);
}

int call_go_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data) {
	int goHmacSha256Update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
	return goHmacSha256Update(hmac_context, data, data_len, user_data);
}

int call_go_hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data) {
	int goHmacSha256Final(void *hmac_context, signal_buffer **output, void *user_data);
	return goHmacSha256Final(hmac_context, output, user_data);
}

void call_hmac_sha256_cleanup(void *hmac_context, void *user_data) {
	int goHmacSha256Cleanup(void *hmac_context, void *user_data);
	goHmacSha256Cleanup(hmac_context, user_data);
}

/// SIGNAL LOCKING FUNCTIONS ///

void call_go_lock(void *user_data) {
	void goLock(void*);
	goLock(user_data);
}

void call_go_unlock(void *user_data) {
	void goUnlock(void*);
	goUnlock(user_data);
}
*/
import "C"
