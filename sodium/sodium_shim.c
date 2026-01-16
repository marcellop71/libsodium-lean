/*
 * sodium_shim.c - C shim for interfacing Lean with libsodium
 *
 * This file provides Lean-compatible FFI wrappers around libsodium functions.
 * libsodium must be installed on the system.
 */

#include <lean/lean.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * Helper functions
 * ============================================================================ */

static inline lean_obj_res mk_option_none(void) {
    return lean_box(0);
}

static inline lean_obj_res mk_option_some(lean_obj_arg a) {
    lean_object *obj = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(obj, 0, a);
    return obj;
}

static inline lean_obj_res mk_except_error(lean_obj_arg e) {
    lean_object *obj = lean_alloc_ctor(0, 1, 0);
    lean_ctor_set(obj, 0, e);
    return obj;
}

static inline lean_obj_res mk_except_ok(lean_obj_arg a) {
    lean_object *obj = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(obj, 0, a);
    return obj;
}

/* Create a ByteArray from raw bytes */
static inline lean_obj_res mk_byte_array(const unsigned char *data, size_t len) {
    lean_object *arr = lean_alloc_sarray(1, len, len);
    if (data && len > 0) {
        memcpy(lean_sarray_cptr(arr), data, len);
    }
    return arr;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_sodium_init(lean_obj_arg world) {
    int result = sodium_init();
    /* sodium_init returns 0 on success, 1 if already initialized, -1 on failure */
    return lean_io_result_mk_ok(lean_box((uint32_t)(result >= 0 ? 1 : 0)));
}

LEAN_EXPORT lean_obj_res lean_sodium_version(lean_obj_arg world) {
    const char *version = sodium_version_string();
    return lean_io_result_mk_ok(lean_mk_string(version));
}

/* ============================================================================
 * Random number generation
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_randombytes_random(lean_obj_arg world) {
    uint32_t r = randombytes_random();
    return lean_io_result_mk_ok(lean_box_uint32(r));
}

LEAN_EXPORT lean_obj_res lean_randombytes_uniform(uint32_t upper_bound, lean_obj_arg world) {
    uint32_t r = randombytes_uniform(upper_bound);
    return lean_io_result_mk_ok(lean_box_uint32(r));
}

LEAN_EXPORT lean_obj_res lean_randombytes_buf(size_t size, lean_obj_arg world) {
    lean_object *arr = lean_alloc_sarray(1, size, size);
    randombytes_buf(lean_sarray_cptr(arr), size);
    return lean_io_result_mk_ok(arr);
}

/* ============================================================================
 * Generic hashing (BLAKE2b)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_generichash(b_lean_obj_arg input,
                                                   b_lean_obj_arg key,
                                                   size_t outlen,
                                                   lean_obj_arg world) {
    size_t inlen = lean_sarray_size(input);
    const unsigned char *in_ptr = lean_sarray_cptr(input);

    size_t keylen = lean_sarray_size(key);
    const unsigned char *key_ptr = keylen > 0 ? lean_sarray_cptr(key) : NULL;

    if (outlen < crypto_generichash_BYTES_MIN || outlen > crypto_generichash_BYTES_MAX) {
        outlen = crypto_generichash_BYTES;
    }

    lean_object *out = lean_alloc_sarray(1, outlen, outlen);

    int result = crypto_generichash(lean_sarray_cptr(out), outlen,
                                    in_ptr, inlen,
                                    key_ptr, keylen);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(out));
}

/* ============================================================================
 * SHA-256
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_hash_sha256(b_lean_obj_arg input, lean_obj_arg world) {
    size_t inlen = lean_sarray_size(input);
    const unsigned char *in_ptr = lean_sarray_cptr(input);

    lean_object *out = lean_alloc_sarray(1, crypto_hash_sha256_BYTES, crypto_hash_sha256_BYTES);

    int result = crypto_hash_sha256(lean_sarray_cptr(out), in_ptr, inlen);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(out));
}

/* ============================================================================
 * SHA-512
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_hash_sha512(b_lean_obj_arg input, lean_obj_arg world) {
    size_t inlen = lean_sarray_size(input);
    const unsigned char *in_ptr = lean_sarray_cptr(input);

    lean_object *out = lean_alloc_sarray(1, crypto_hash_sha512_BYTES, crypto_hash_sha512_BYTES);

    int result = crypto_hash_sha512(lean_sarray_cptr(out), in_ptr, inlen);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(out));
}

/* ============================================================================
 * Secret-key authenticated encryption (secretbox)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_secretbox_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
    crypto_secretbox_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_secretbox_easy(b_lean_obj_arg message,
                                                     b_lean_obj_arg nonce,
                                                     b_lean_obj_arg key,
                                                     lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *n = lean_sarray_cptr(nonce);
    const unsigned char *k = lean_sarray_cptr(key);

    if (lean_sarray_size(nonce) != crypto_secretbox_NONCEBYTES ||
        lean_sarray_size(key) != crypto_secretbox_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t clen = mlen + crypto_secretbox_MACBYTES;
    lean_object *ciphertext = lean_alloc_sarray(1, clen, clen);

    int result = crypto_secretbox_easy(lean_sarray_cptr(ciphertext), m, mlen, n, k);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(ciphertext));
}

LEAN_EXPORT lean_obj_res lean_crypto_secretbox_open_easy(b_lean_obj_arg ciphertext,
                                                          b_lean_obj_arg nonce,
                                                          b_lean_obj_arg key,
                                                          lean_obj_arg world) {
    size_t clen = lean_sarray_size(ciphertext);
    const unsigned char *c = lean_sarray_cptr(ciphertext);
    const unsigned char *n = lean_sarray_cptr(nonce);
    const unsigned char *k = lean_sarray_cptr(key);

    if (clen < crypto_secretbox_MACBYTES ||
        lean_sarray_size(nonce) != crypto_secretbox_NONCEBYTES ||
        lean_sarray_size(key) != crypto_secretbox_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t mlen = clen - crypto_secretbox_MACBYTES;
    lean_object *message = lean_alloc_sarray(1, mlen, mlen);

    int result = crypto_secretbox_open_easy(lean_sarray_cptr(message), c, clen, n, k);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(message));
}

/* ============================================================================
 * Public-key authenticated encryption (box)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_box_keypair(lean_obj_arg world) {
    lean_object *pk = lean_alloc_sarray(1, crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
    lean_object *sk = lean_alloc_sarray(1, crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);

    int result = crypto_box_keypair(lean_sarray_cptr(pk), lean_sarray_cptr(sk));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    /* Return a pair (pk, sk) */
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, pk);
    lean_ctor_set(pair, 1, sk);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_box_easy(b_lean_obj_arg message,
                                               b_lean_obj_arg nonce,
                                               b_lean_obj_arg pk,
                                               b_lean_obj_arg sk,
                                               lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *n = lean_sarray_cptr(nonce);
    const unsigned char *recipient_pk = lean_sarray_cptr(pk);
    const unsigned char *sender_sk = lean_sarray_cptr(sk);

    if (lean_sarray_size(nonce) != crypto_box_NONCEBYTES ||
        lean_sarray_size(pk) != crypto_box_PUBLICKEYBYTES ||
        lean_sarray_size(sk) != crypto_box_SECRETKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t clen = mlen + crypto_box_MACBYTES;
    lean_object *ciphertext = lean_alloc_sarray(1, clen, clen);

    int result = crypto_box_easy(lean_sarray_cptr(ciphertext), m, mlen, n, recipient_pk, sender_sk);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(ciphertext));
}

LEAN_EXPORT lean_obj_res lean_crypto_box_open_easy(b_lean_obj_arg ciphertext,
                                                    b_lean_obj_arg nonce,
                                                    b_lean_obj_arg pk,
                                                    b_lean_obj_arg sk,
                                                    lean_obj_arg world) {
    size_t clen = lean_sarray_size(ciphertext);
    const unsigned char *c = lean_sarray_cptr(ciphertext);
    const unsigned char *n = lean_sarray_cptr(nonce);
    const unsigned char *sender_pk = lean_sarray_cptr(pk);
    const unsigned char *recipient_sk = lean_sarray_cptr(sk);

    if (clen < crypto_box_MACBYTES ||
        lean_sarray_size(nonce) != crypto_box_NONCEBYTES ||
        lean_sarray_size(pk) != crypto_box_PUBLICKEYBYTES ||
        lean_sarray_size(sk) != crypto_box_SECRETKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t mlen = clen - crypto_box_MACBYTES;
    lean_object *message = lean_alloc_sarray(1, mlen, mlen);

    int result = crypto_box_open_easy(lean_sarray_cptr(message), c, clen, n, sender_pk, recipient_sk);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(message));
}

/* ============================================================================
 * Sealed boxes (anonymous sender)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_box_seal(b_lean_obj_arg message,
                                               b_lean_obj_arg pk,
                                               lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *recipient_pk = lean_sarray_cptr(pk);

    if (lean_sarray_size(pk) != crypto_box_PUBLICKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t clen = mlen + crypto_box_SEALBYTES;
    lean_object *ciphertext = lean_alloc_sarray(1, clen, clen);

    int result = crypto_box_seal(lean_sarray_cptr(ciphertext), m, mlen, recipient_pk);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(ciphertext));
}

LEAN_EXPORT lean_obj_res lean_crypto_box_seal_open(b_lean_obj_arg ciphertext,
                                                    b_lean_obj_arg pk,
                                                    b_lean_obj_arg sk,
                                                    lean_obj_arg world) {
    size_t clen = lean_sarray_size(ciphertext);
    const unsigned char *c = lean_sarray_cptr(ciphertext);
    const unsigned char *recipient_pk = lean_sarray_cptr(pk);
    const unsigned char *recipient_sk = lean_sarray_cptr(sk);

    if (clen < crypto_box_SEALBYTES ||
        lean_sarray_size(pk) != crypto_box_PUBLICKEYBYTES ||
        lean_sarray_size(sk) != crypto_box_SECRETKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t mlen = clen - crypto_box_SEALBYTES;
    lean_object *message = lean_alloc_sarray(1, mlen, mlen);

    int result = crypto_box_seal_open(lean_sarray_cptr(message), c, clen, recipient_pk, recipient_sk);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(message));
}

/* ============================================================================
 * Digital signatures (Ed25519)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_sign_keypair(lean_obj_arg world) {
    lean_object *pk = lean_alloc_sarray(1, crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES);
    lean_object *sk = lean_alloc_sarray(1, crypto_sign_SECRETKEYBYTES, crypto_sign_SECRETKEYBYTES);

    int result = crypto_sign_keypair(lean_sarray_cptr(pk), lean_sarray_cptr(sk));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, pk);
    lean_ctor_set(pair, 1, sk);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_sign_detached(b_lean_obj_arg message,
                                                    b_lean_obj_arg sk,
                                                    lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *secret_key = lean_sarray_cptr(sk);

    if (lean_sarray_size(sk) != crypto_sign_SECRETKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *sig = lean_alloc_sarray(1, crypto_sign_BYTES, crypto_sign_BYTES);
    unsigned long long siglen;

    int result = crypto_sign_detached(lean_sarray_cptr(sig), &siglen, m, mlen, secret_key);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(sig));
}

LEAN_EXPORT lean_obj_res lean_crypto_sign_verify_detached(b_lean_obj_arg sig,
                                                           b_lean_obj_arg message,
                                                           b_lean_obj_arg pk,
                                                           lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *signature = lean_sarray_cptr(sig);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *public_key = lean_sarray_cptr(pk);

    if (lean_sarray_size(sig) != crypto_sign_BYTES ||
        lean_sarray_size(pk) != crypto_sign_PUBLICKEYBYTES) {
        return lean_io_result_mk_ok(lean_box(0));
    }

    int result = crypto_sign_verify_detached(signature, m, mlen, public_key);

    return lean_io_result_mk_ok(lean_box((uint32_t)(result == 0 ? 1 : 0)));
}

/* ============================================================================
 * Message authentication (HMAC-SHA512-256)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_auth_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1, crypto_auth_KEYBYTES, crypto_auth_KEYBYTES);
    crypto_auth_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_auth(b_lean_obj_arg message,
                                           b_lean_obj_arg key,
                                           lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *k = lean_sarray_cptr(key);

    if (lean_sarray_size(key) != crypto_auth_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *tag = lean_alloc_sarray(1, crypto_auth_BYTES, crypto_auth_BYTES);

    int result = crypto_auth(lean_sarray_cptr(tag), m, mlen, k);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(tag));
}

LEAN_EXPORT lean_obj_res lean_crypto_auth_verify(b_lean_obj_arg tag,
                                                  b_lean_obj_arg message,
                                                  b_lean_obj_arg key,
                                                  lean_obj_arg world) {
    size_t mlen = lean_sarray_size(message);
    const unsigned char *t = lean_sarray_cptr(tag);
    const unsigned char *m = lean_sarray_cptr(message);
    const unsigned char *k = lean_sarray_cptr(key);

    if (lean_sarray_size(tag) != crypto_auth_BYTES ||
        lean_sarray_size(key) != crypto_auth_KEYBYTES) {
        return lean_io_result_mk_ok(lean_box(0));
    }

    int result = crypto_auth_verify(t, m, mlen, k);

    return lean_io_result_mk_ok(lean_box((uint32_t)(result == 0 ? 1 : 0)));
}

/* ============================================================================
 * Password hashing (Argon2id)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_pwhash(b_lean_obj_arg password,
                                             b_lean_obj_arg salt,
                                             size_t outlen,
                                             uint64_t opslimit,
                                             size_t memlimit,
                                             lean_obj_arg world) {
    size_t pwlen = lean_sarray_size(password);
    const char *pw = (const char *)lean_sarray_cptr(password);
    const unsigned char *s = lean_sarray_cptr(salt);

    if (lean_sarray_size(salt) != crypto_pwhash_SALTBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *key = lean_alloc_sarray(1, outlen, outlen);

    int result = crypto_pwhash(lean_sarray_cptr(key), outlen,
                               pw, pwlen, s,
                               opslimit, memlimit,
                               crypto_pwhash_ALG_DEFAULT);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(key));
}

LEAN_EXPORT lean_obj_res lean_crypto_pwhash_str(b_lean_obj_arg password,
                                                 uint64_t opslimit,
                                                 size_t memlimit,
                                                 lean_obj_arg world) {
    size_t pwlen = lean_sarray_size(password);
    const char *pw = (const char *)lean_sarray_cptr(password);

    char hashed[crypto_pwhash_STRBYTES];

    int result = crypto_pwhash_str(hashed, pw, pwlen, opslimit, memlimit);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(lean_mk_string(hashed)));
}

LEAN_EXPORT lean_obj_res lean_crypto_pwhash_str_verify(b_lean_obj_arg hash,
                                                        b_lean_obj_arg password,
                                                        lean_obj_arg world) {
    const char *h = lean_string_cstr(hash);
    size_t pwlen = lean_sarray_size(password);
    const char *pw = (const char *)lean_sarray_cptr(password);

    int result = crypto_pwhash_str_verify(h, pw, pwlen);

    return lean_io_result_mk_ok(lean_box((uint32_t)(result == 0 ? 1 : 0)));
}

/* ============================================================================
 * Key derivation (HKDF-like)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_kdf_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1, crypto_kdf_KEYBYTES, crypto_kdf_KEYBYTES);
    crypto_kdf_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_kdf_derive_from_key(size_t subkey_len,
                                                          uint64_t subkey_id,
                                                          b_lean_obj_arg ctx,
                                                          b_lean_obj_arg key,
                                                          lean_obj_arg world) {
    const char *context = lean_string_cstr(ctx);
    const unsigned char *master_key = lean_sarray_cptr(key);

    if (lean_sarray_size(key) != crypto_kdf_KEYBYTES ||
        subkey_len < crypto_kdf_BYTES_MIN ||
        subkey_len > crypto_kdf_BYTES_MAX) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *subkey = lean_alloc_sarray(1, subkey_len, subkey_len);

    int result = crypto_kdf_derive_from_key(lean_sarray_cptr(subkey), subkey_len,
                                            subkey_id, context, master_key);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(subkey));
}

/* ============================================================================
 * Utilities
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_sodium_memzero(lean_obj_arg data, lean_obj_arg world) {
    /* Note: This operates on a copy, not the original.
       For actual secure memory zeroing, use dedicated secure memory APIs */
    size_t len = lean_sarray_size(data);
    lean_object *zeroed = lean_alloc_sarray(1, len, len);
    sodium_memzero(lean_sarray_cptr(zeroed), len);
    return lean_io_result_mk_ok(zeroed);
}

LEAN_EXPORT lean_obj_res lean_sodium_bin2hex(b_lean_obj_arg bin, lean_obj_arg world) {
    size_t bin_len = lean_sarray_size(bin);
    const unsigned char *bin_ptr = lean_sarray_cptr(bin);

    size_t hex_len = bin_len * 2 + 1;
    char *hex = malloc(hex_len);
    if (!hex) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    sodium_bin2hex(hex, hex_len, bin_ptr, bin_len);
    lean_object *result = lean_mk_string(hex);
    free(hex);

    return lean_io_result_mk_ok(mk_option_some(result));
}

LEAN_EXPORT lean_obj_res lean_sodium_hex2bin(b_lean_obj_arg hex, lean_obj_arg world) {
    const char *hex_str = lean_string_cstr(hex);
    size_t hex_len = strlen(hex_str);
    size_t bin_maxlen = hex_len / 2;

    lean_object *bin = lean_alloc_sarray(1, bin_maxlen, bin_maxlen);
    size_t bin_len;

    int result = sodium_hex2bin(lean_sarray_cptr(bin), bin_maxlen,
                                hex_str, hex_len,
                                NULL, &bin_len, NULL);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    /* Resize if needed */
    if (bin_len < bin_maxlen) {
        lean_object *resized = lean_alloc_sarray(1, bin_len, bin_len);
        memcpy(lean_sarray_cptr(resized), lean_sarray_cptr(bin), bin_len);
        return lean_io_result_mk_ok(mk_option_some(resized));
    }

    return lean_io_result_mk_ok(mk_option_some(bin));
}

/* Constant-time comparison */
LEAN_EXPORT lean_obj_res lean_sodium_memcmp(b_lean_obj_arg a, b_lean_obj_arg b, lean_obj_arg world) {
    size_t len_a = lean_sarray_size(a);
    size_t len_b = lean_sarray_size(b);

    if (len_a != len_b) {
        return lean_io_result_mk_ok(lean_box(0));
    }

    int result = sodium_memcmp(lean_sarray_cptr(a), lean_sarray_cptr(b), len_a);

    return lean_io_result_mk_ok(lean_box((uint32_t)(result == 0 ? 1 : 0)));
}

/* ============================================================================
 * Constants
 * ============================================================================ */

LEAN_EXPORT uint32_t lean_crypto_secretbox_keybytes(void) {
    return crypto_secretbox_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_secretbox_noncebytes(void) {
    return crypto_secretbox_NONCEBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_secretbox_macbytes(void) {
    return crypto_secretbox_MACBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_box_publickeybytes(void) {
    return crypto_box_PUBLICKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_box_secretkeybytes(void) {
    return crypto_box_SECRETKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_box_noncebytes(void) {
    return crypto_box_NONCEBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_box_macbytes(void) {
    return crypto_box_MACBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_box_sealbytes(void) {
    return crypto_box_SEALBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_sign_publickeybytes(void) {
    return crypto_sign_PUBLICKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_sign_secretkeybytes(void) {
    return crypto_sign_SECRETKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_sign_bytes(void) {
    return crypto_sign_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_auth_keybytes(void) {
    return crypto_auth_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_auth_bytes(void) {
    return crypto_auth_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_pwhash_saltbytes(void) {
    return crypto_pwhash_SALTBYTES;
}

LEAN_EXPORT uint64_t lean_crypto_pwhash_opslimit_interactive(void) {
    return crypto_pwhash_OPSLIMIT_INTERACTIVE;
}

LEAN_EXPORT uint64_t lean_crypto_pwhash_opslimit_moderate(void) {
    return crypto_pwhash_OPSLIMIT_MODERATE;
}

LEAN_EXPORT uint64_t lean_crypto_pwhash_opslimit_sensitive(void) {
    return crypto_pwhash_OPSLIMIT_SENSITIVE;
}

LEAN_EXPORT size_t lean_crypto_pwhash_memlimit_interactive(void) {
    return crypto_pwhash_MEMLIMIT_INTERACTIVE;
}

LEAN_EXPORT size_t lean_crypto_pwhash_memlimit_moderate(void) {
    return crypto_pwhash_MEMLIMIT_MODERATE;
}

LEAN_EXPORT size_t lean_crypto_pwhash_memlimit_sensitive(void) {
    return crypto_pwhash_MEMLIMIT_SENSITIVE;
}

LEAN_EXPORT uint32_t lean_crypto_generichash_bytes(void) {
    return crypto_generichash_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_generichash_bytes_min(void) {
    return crypto_generichash_BYTES_MIN;
}

LEAN_EXPORT uint32_t lean_crypto_generichash_bytes_max(void) {
    return crypto_generichash_BYTES_MAX;
}

LEAN_EXPORT uint32_t lean_crypto_generichash_keybytes(void) {
    return crypto_generichash_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_hash_sha256_bytes(void) {
    return crypto_hash_sha256_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_hash_sha512_bytes(void) {
    return crypto_hash_sha512_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_kdf_keybytes(void) {
    return crypto_kdf_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_kdf_bytes_min(void) {
    return crypto_kdf_BYTES_MIN;
}

LEAN_EXPORT uint32_t lean_crypto_kdf_bytes_max(void) {
    return crypto_kdf_BYTES_MAX;
}

/* ============================================================================
 * SecretStream (XChaCha20-Poly1305)
 * ============================================================================ */

/* State wrapper for secretstream - stored as external object */
typedef struct {
    crypto_secretstream_xchacha20poly1305_state state;
} lean_secretstream_state;

static void lean_secretstream_state_finalize(void *ptr) {
    lean_secretstream_state *s = (lean_secretstream_state *)ptr;
    sodium_memzero(&s->state, sizeof(s->state));
    free(s);
}

static void lean_secretstream_state_foreach(void *ptr, b_lean_obj_arg f) {
    /* No nested Lean objects to traverse */
}

static lean_external_class *g_secretstream_state_class = NULL;

static inline lean_external_class *get_secretstream_state_class(void) {
    if (g_secretstream_state_class == NULL) {
        g_secretstream_state_class = lean_register_external_class(
            lean_secretstream_state_finalize,
            lean_secretstream_state_foreach);
    }
    return g_secretstream_state_class;
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1,
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
        crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_secretstream_xchacha20poly1305_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_init_push(b_lean_obj_arg key,
                                                             lean_obj_arg world) {
    if (lean_sarray_size(key) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_secretstream_state *s = malloc(sizeof(lean_secretstream_state));
    if (!s) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *header = lean_alloc_sarray(1,
        crypto_secretstream_xchacha20poly1305_HEADERBYTES,
        crypto_secretstream_xchacha20poly1305_HEADERBYTES);

    int result = crypto_secretstream_xchacha20poly1305_init_push(
        &s->state,
        lean_sarray_cptr(header),
        lean_sarray_cptr(key));

    if (result != 0) {
        free(s);
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *state_obj = lean_alloc_external(get_secretstream_state_class(), s);

    /* Return a pair (state, header) */
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, state_obj);
    lean_ctor_set(pair, 1, header);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_push(lean_obj_arg state_obj,
                                                        b_lean_obj_arg message,
                                                        b_lean_obj_arg ad,
                                                        uint8_t tag,
                                                        lean_obj_arg world) {
    lean_secretstream_state *s = (lean_secretstream_state *)lean_get_external_data(state_obj);

    size_t mlen = lean_sarray_size(message);
    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    size_t clen = mlen + crypto_secretstream_xchacha20poly1305_ABYTES;
    lean_object *ciphertext = lean_alloc_sarray(1, clen, clen);

    int result = crypto_secretstream_xchacha20poly1305_push(
        &s->state,
        lean_sarray_cptr(ciphertext), NULL,
        lean_sarray_cptr(message), mlen,
        ad_ptr, adlen,
        tag);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(ciphertext));
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_init_pull(b_lean_obj_arg header,
                                                             b_lean_obj_arg key,
                                                             lean_obj_arg world) {
    if (lean_sarray_size(header) != crypto_secretstream_xchacha20poly1305_HEADERBYTES ||
        lean_sarray_size(key) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_secretstream_state *s = malloc(sizeof(lean_secretstream_state));
    if (!s) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    int result = crypto_secretstream_xchacha20poly1305_init_pull(
        &s->state,
        lean_sarray_cptr(header),
        lean_sarray_cptr(key));

    if (result != 0) {
        free(s);
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *state_obj = lean_alloc_external(get_secretstream_state_class(), s);
    return lean_io_result_mk_ok(mk_option_some(state_obj));
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_pull(lean_obj_arg state_obj,
                                                        b_lean_obj_arg ciphertext,
                                                        b_lean_obj_arg ad,
                                                        lean_obj_arg world) {
    lean_secretstream_state *s = (lean_secretstream_state *)lean_get_external_data(state_obj);

    size_t clen = lean_sarray_size(ciphertext);
    if (clen < crypto_secretstream_xchacha20poly1305_ABYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    size_t mlen = clen - crypto_secretstream_xchacha20poly1305_ABYTES;
    lean_object *message = lean_alloc_sarray(1, mlen, mlen);
    unsigned char tag;

    int result = crypto_secretstream_xchacha20poly1305_pull(
        &s->state,
        lean_sarray_cptr(message), NULL,
        &tag,
        lean_sarray_cptr(ciphertext), clen,
        ad_ptr, adlen);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    /* Return a pair (message, tag) */
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, message);
    lean_ctor_set(pair, 1, lean_box((uint32_t)tag));
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_secretstream_rekey(lean_obj_arg state_obj,
                                                         lean_obj_arg world) {
    lean_secretstream_state *s = (lean_secretstream_state *)lean_get_external_data(state_obj);
    crypto_secretstream_xchacha20poly1305_rekey(&s->state);
    return lean_io_result_mk_ok(lean_box(0));
}

/* SecretStream constants */
LEAN_EXPORT uint32_t lean_crypto_secretstream_keybytes(void) {
    return crypto_secretstream_xchacha20poly1305_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_secretstream_headerbytes(void) {
    return crypto_secretstream_xchacha20poly1305_HEADERBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_secretstream_abytes(void) {
    return crypto_secretstream_xchacha20poly1305_ABYTES;
}

LEAN_EXPORT uint8_t lean_crypto_secretstream_tag_message(void) {
    return crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
}

LEAN_EXPORT uint8_t lean_crypto_secretstream_tag_push(void) {
    return crypto_secretstream_xchacha20poly1305_TAG_PUSH;
}

LEAN_EXPORT uint8_t lean_crypto_secretstream_tag_rekey(void) {
    return crypto_secretstream_xchacha20poly1305_TAG_REKEY;
}

LEAN_EXPORT uint8_t lean_crypto_secretstream_tag_final(void) {
    return crypto_secretstream_xchacha20poly1305_TAG_FINAL;
}

/* ============================================================================
 * Key Exchange (X25519 + BLAKE2b)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_kx_keypair(lean_obj_arg world) {
    lean_object *pk = lean_alloc_sarray(1, crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
    lean_object *sk = lean_alloc_sarray(1, crypto_kx_SECRETKEYBYTES, crypto_kx_SECRETKEYBYTES);

    int result = crypto_kx_keypair(lean_sarray_cptr(pk), lean_sarray_cptr(sk));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, pk);
    lean_ctor_set(pair, 1, sk);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_kx_seed_keypair(b_lean_obj_arg seed,
                                                      lean_obj_arg world) {
    if (lean_sarray_size(seed) != crypto_kx_SEEDBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pk = lean_alloc_sarray(1, crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
    lean_object *sk = lean_alloc_sarray(1, crypto_kx_SECRETKEYBYTES, crypto_kx_SECRETKEYBYTES);

    int result = crypto_kx_seed_keypair(
        lean_sarray_cptr(pk),
        lean_sarray_cptr(sk),
        lean_sarray_cptr(seed));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, pk);
    lean_ctor_set(pair, 1, sk);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_kx_client_session_keys(b_lean_obj_arg client_pk,
                                                             b_lean_obj_arg client_sk,
                                                             b_lean_obj_arg server_pk,
                                                             lean_obj_arg world) {
    if (lean_sarray_size(client_pk) != crypto_kx_PUBLICKEYBYTES ||
        lean_sarray_size(client_sk) != crypto_kx_SECRETKEYBYTES ||
        lean_sarray_size(server_pk) != crypto_kx_PUBLICKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *rx = lean_alloc_sarray(1, crypto_kx_SESSIONKEYBYTES, crypto_kx_SESSIONKEYBYTES);
    lean_object *tx = lean_alloc_sarray(1, crypto_kx_SESSIONKEYBYTES, crypto_kx_SESSIONKEYBYTES);

    int result = crypto_kx_client_session_keys(
        lean_sarray_cptr(rx),
        lean_sarray_cptr(tx),
        lean_sarray_cptr(client_pk),
        lean_sarray_cptr(client_sk),
        lean_sarray_cptr(server_pk));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, rx);
    lean_ctor_set(pair, 1, tx);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_kx_server_session_keys(b_lean_obj_arg server_pk,
                                                             b_lean_obj_arg server_sk,
                                                             b_lean_obj_arg client_pk,
                                                             lean_obj_arg world) {
    if (lean_sarray_size(server_pk) != crypto_kx_PUBLICKEYBYTES ||
        lean_sarray_size(server_sk) != crypto_kx_SECRETKEYBYTES ||
        lean_sarray_size(client_pk) != crypto_kx_PUBLICKEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *rx = lean_alloc_sarray(1, crypto_kx_SESSIONKEYBYTES, crypto_kx_SESSIONKEYBYTES);
    lean_object *tx = lean_alloc_sarray(1, crypto_kx_SESSIONKEYBYTES, crypto_kx_SESSIONKEYBYTES);

    int result = crypto_kx_server_session_keys(
        lean_sarray_cptr(rx),
        lean_sarray_cptr(tx),
        lean_sarray_cptr(server_pk),
        lean_sarray_cptr(server_sk),
        lean_sarray_cptr(client_pk));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, rx);
    lean_ctor_set(pair, 1, tx);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

/* Key Exchange constants */
LEAN_EXPORT uint32_t lean_crypto_kx_publickeybytes(void) {
    return crypto_kx_PUBLICKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_kx_secretkeybytes(void) {
    return crypto_kx_SECRETKEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_kx_seedbytes(void) {
    return crypto_kx_SEEDBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_kx_sessionkeybytes(void) {
    return crypto_kx_SESSIONKEYBYTES;
}

/* ============================================================================
 * Streaming/Incremental Hash (BLAKE2b)
 * ============================================================================ */

/* State wrapper for generichash streaming */
typedef struct {
    crypto_generichash_state state;
} lean_generichash_state;

static void lean_generichash_state_finalize(void *ptr) {
    lean_generichash_state *s = (lean_generichash_state *)ptr;
    sodium_memzero(&s->state, sizeof(s->state));
    free(s);
}

static void lean_generichash_state_foreach(void *ptr, b_lean_obj_arg f) {
    /* No nested Lean objects */
}

static lean_external_class *g_generichash_state_class = NULL;

static inline lean_external_class *get_generichash_state_class(void) {
    if (g_generichash_state_class == NULL) {
        g_generichash_state_class = lean_register_external_class(
            lean_generichash_state_finalize,
            lean_generichash_state_foreach);
    }
    return g_generichash_state_class;
}

LEAN_EXPORT lean_obj_res lean_crypto_generichash_init(b_lean_obj_arg key,
                                                       size_t outlen,
                                                       lean_obj_arg world) {
    size_t keylen = lean_sarray_size(key);
    const unsigned char *key_ptr = keylen > 0 ? lean_sarray_cptr(key) : NULL;

    if (outlen < crypto_generichash_BYTES_MIN || outlen > crypto_generichash_BYTES_MAX) {
        outlen = crypto_generichash_BYTES;
    }

    lean_generichash_state *s = malloc(sizeof(lean_generichash_state));
    if (!s) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    int result = crypto_generichash_init(&s->state, key_ptr, keylen, outlen);

    if (result != 0) {
        free(s);
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *state_obj = lean_alloc_external(get_generichash_state_class(), s);

    /* Return pair (state, outlen) so we remember the output length */
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, state_obj);
    lean_ctor_set(pair, 1, lean_box_usize(outlen));
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_generichash_update(lean_obj_arg state_obj,
                                                         b_lean_obj_arg input,
                                                         lean_obj_arg world) {
    lean_generichash_state *s = (lean_generichash_state *)lean_get_external_data(state_obj);

    size_t inlen = lean_sarray_size(input);

    int result = crypto_generichash_update(&s->state, lean_sarray_cptr(input), inlen);

    if (result != 0) {
        return lean_io_result_mk_ok(lean_box(0));
    }
    return lean_io_result_mk_ok(lean_box(1));
}

LEAN_EXPORT lean_obj_res lean_crypto_generichash_final(lean_obj_arg state_obj,
                                                        size_t outlen,
                                                        lean_obj_arg world) {
    lean_generichash_state *s = (lean_generichash_state *)lean_get_external_data(state_obj);

    lean_object *out = lean_alloc_sarray(1, outlen, outlen);

    int result = crypto_generichash_final(&s->state, lean_sarray_cptr(out), outlen);

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(out));
}

/* ============================================================================
 * Short-Input Hashing (SipHash)
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_shorthash_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1, crypto_shorthash_KEYBYTES, crypto_shorthash_KEYBYTES);
    crypto_shorthash_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_shorthash(b_lean_obj_arg input,
                                                b_lean_obj_arg key,
                                                lean_obj_arg world) {
    if (lean_sarray_size(key) != crypto_shorthash_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    lean_object *out = lean_alloc_sarray(1, crypto_shorthash_BYTES, crypto_shorthash_BYTES);

    int result = crypto_shorthash(
        lean_sarray_cptr(out),
        lean_sarray_cptr(input),
        lean_sarray_size(input),
        lean_sarray_cptr(key));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(out));
}

/* Short hash constants */
LEAN_EXPORT uint32_t lean_crypto_shorthash_bytes(void) {
    return crypto_shorthash_BYTES;
}

LEAN_EXPORT uint32_t lean_crypto_shorthash_keybytes(void) {
    return crypto_shorthash_KEYBYTES;
}

/* ============================================================================
 * AEAD XChaCha20-Poly1305-IETF
 * ============================================================================ */

LEAN_EXPORT lean_obj_res lean_crypto_aead_xchacha20poly1305_keygen(lean_obj_arg world) {
    lean_object *key = lean_alloc_sarray(1,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_aead_xchacha20poly1305_ietf_keygen(lean_sarray_cptr(key));
    return lean_io_result_mk_ok(key);
}

LEAN_EXPORT lean_obj_res lean_crypto_aead_xchacha20poly1305_encrypt(
        b_lean_obj_arg message,
        b_lean_obj_arg ad,
        b_lean_obj_arg nonce,
        b_lean_obj_arg key,
        lean_obj_arg world) {
    if (lean_sarray_size(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        lean_sarray_size(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t mlen = lean_sarray_size(message);
    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    size_t clen = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    lean_object *ciphertext = lean_alloc_sarray(1, clen, clen);

    unsigned long long actual_clen;
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
        lean_sarray_cptr(ciphertext), &actual_clen,
        lean_sarray_cptr(message), mlen,
        ad_ptr, adlen,
        NULL, /* nsec - not used */
        lean_sarray_cptr(nonce),
        lean_sarray_cptr(key));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(ciphertext));
}

LEAN_EXPORT lean_obj_res lean_crypto_aead_xchacha20poly1305_decrypt(
        b_lean_obj_arg ciphertext,
        b_lean_obj_arg ad,
        b_lean_obj_arg nonce,
        b_lean_obj_arg key,
        lean_obj_arg world) {
    size_t clen = lean_sarray_size(ciphertext);

    if (clen < crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        lean_sarray_size(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        lean_sarray_size(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    size_t mlen = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    lean_object *message = lean_alloc_sarray(1, mlen, mlen);

    unsigned long long actual_mlen;
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        lean_sarray_cptr(message), &actual_mlen,
        NULL, /* nsec - not used */
        lean_sarray_cptr(ciphertext), clen,
        ad_ptr, adlen,
        lean_sarray_cptr(nonce),
        lean_sarray_cptr(key));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(message));
}

LEAN_EXPORT lean_obj_res lean_crypto_aead_xchacha20poly1305_encrypt_detached(
        b_lean_obj_arg message,
        b_lean_obj_arg ad,
        b_lean_obj_arg nonce,
        b_lean_obj_arg key,
        lean_obj_arg world) {
    if (lean_sarray_size(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        lean_sarray_size(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t mlen = lean_sarray_size(message);
    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    lean_object *ciphertext = lean_alloc_sarray(1, mlen, mlen);
    lean_object *mac = lean_alloc_sarray(1,
        crypto_aead_xchacha20poly1305_ietf_ABYTES,
        crypto_aead_xchacha20poly1305_ietf_ABYTES);

    unsigned long long maclen;
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        lean_sarray_cptr(ciphertext),
        lean_sarray_cptr(mac), &maclen,
        lean_sarray_cptr(message), mlen,
        ad_ptr, adlen,
        NULL, /* nsec */
        lean_sarray_cptr(nonce),
        lean_sarray_cptr(key));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    /* Return pair (ciphertext, mac) */
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, ciphertext);
    lean_ctor_set(pair, 1, mac);
    return lean_io_result_mk_ok(mk_option_some(pair));
}

LEAN_EXPORT lean_obj_res lean_crypto_aead_xchacha20poly1305_decrypt_detached(
        b_lean_obj_arg ciphertext,
        b_lean_obj_arg mac,
        b_lean_obj_arg ad,
        b_lean_obj_arg nonce,
        b_lean_obj_arg key,
        lean_obj_arg world) {
    if (lean_sarray_size(mac) != crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        lean_sarray_size(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        lean_sarray_size(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return lean_io_result_mk_ok(mk_option_none());
    }

    size_t clen = lean_sarray_size(ciphertext);
    size_t adlen = lean_sarray_size(ad);
    const unsigned char *ad_ptr = adlen > 0 ? lean_sarray_cptr(ad) : NULL;

    lean_object *message = lean_alloc_sarray(1, clen, clen);

    int result = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        lean_sarray_cptr(message),
        NULL, /* nsec */
        lean_sarray_cptr(ciphertext), clen,
        lean_sarray_cptr(mac),
        ad_ptr, adlen,
        lean_sarray_cptr(nonce),
        lean_sarray_cptr(key));

    if (result != 0) {
        return lean_io_result_mk_ok(mk_option_none());
    }
    return lean_io_result_mk_ok(mk_option_some(message));
}

/* AEAD constants */
LEAN_EXPORT uint32_t lean_crypto_aead_xchacha20poly1305_keybytes(void) {
    return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_aead_xchacha20poly1305_npubbytes(void) {
    return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

LEAN_EXPORT uint32_t lean_crypto_aead_xchacha20poly1305_abytes(void) {
    return crypto_aead_xchacha20poly1305_ietf_ABYTES;
}
