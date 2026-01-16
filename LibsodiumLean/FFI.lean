/-
  LibsodiumLean/FFI.lean - Low-level FFI bindings to libsodium
-/

namespace Sodium.FFI

-- ============================================================================
-- Initialization
-- ============================================================================

@[extern "lean_sodium_init"]
opaque sodium_init : IO Bool

@[extern "lean_sodium_version"]
opaque sodium_version : IO String

-- ============================================================================
-- Random number generation
-- ============================================================================

@[extern "lean_randombytes_random"]
opaque randombytes_random : IO UInt32

@[extern "lean_randombytes_uniform"]
opaque randombytes_uniform : UInt32 → IO UInt32

@[extern "lean_randombytes_buf"]
opaque randombytes_buf : USize → IO ByteArray

-- ============================================================================
-- Generic hashing (BLAKE2b)
-- ============================================================================

@[extern "lean_crypto_generichash"]
opaque crypto_generichash : @&ByteArray → @&ByteArray → USize → IO (Option ByteArray)

-- ============================================================================
-- SHA-256 / SHA-512
-- ============================================================================

@[extern "lean_crypto_hash_sha256"]
opaque crypto_hash_sha256 : @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_hash_sha512"]
opaque crypto_hash_sha512 : @&ByteArray → IO (Option ByteArray)

-- ============================================================================
-- Secret-key authenticated encryption (secretbox)
-- ============================================================================

@[extern "lean_crypto_secretbox_keygen"]
opaque crypto_secretbox_keygen : IO ByteArray

@[extern "lean_crypto_secretbox_easy"]
opaque crypto_secretbox_easy : @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_secretbox_open_easy"]
opaque crypto_secretbox_open_easy : @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

-- ============================================================================
-- Public-key authenticated encryption (box)
-- ============================================================================

@[extern "lean_crypto_box_keypair"]
opaque crypto_box_keypair : IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_box_easy"]
opaque crypto_box_easy : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_box_open_easy"]
opaque crypto_box_open_easy : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

-- ============================================================================
-- Sealed boxes (anonymous sender)
-- ============================================================================

@[extern "lean_crypto_box_seal"]
opaque crypto_box_seal : @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_box_seal_open"]
opaque crypto_box_seal_open : @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

-- ============================================================================
-- Digital signatures (Ed25519)
-- ============================================================================

@[extern "lean_crypto_sign_keypair"]
opaque crypto_sign_keypair : IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_sign_detached"]
opaque crypto_sign_detached : @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_sign_verify_detached"]
opaque crypto_sign_verify_detached : @&ByteArray → @&ByteArray → @&ByteArray → IO Bool

-- ============================================================================
-- Message authentication (HMAC-SHA512-256)
-- ============================================================================

@[extern "lean_crypto_auth_keygen"]
opaque crypto_auth_keygen : IO ByteArray

@[extern "lean_crypto_auth"]
opaque crypto_auth : @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_auth_verify"]
opaque crypto_auth_verify : @&ByteArray → @&ByteArray → @&ByteArray → IO Bool

-- ============================================================================
-- Password hashing (Argon2id)
-- ============================================================================

@[extern "lean_crypto_pwhash"]
opaque crypto_pwhash : @&ByteArray → @&ByteArray → USize → UInt64 → USize → IO (Option ByteArray)

@[extern "lean_crypto_pwhash_str"]
opaque crypto_pwhash_str : @&ByteArray → UInt64 → USize → IO (Option String)

@[extern "lean_crypto_pwhash_str_verify"]
opaque crypto_pwhash_str_verify : @&String → @&ByteArray → IO Bool

-- ============================================================================
-- Key derivation
-- ============================================================================

@[extern "lean_crypto_kdf_keygen"]
opaque crypto_kdf_keygen : IO ByteArray

@[extern "lean_crypto_kdf_derive_from_key"]
opaque crypto_kdf_derive_from_key : USize → UInt64 → @&String → @&ByteArray → IO (Option ByteArray)

-- ============================================================================
-- Utilities
-- ============================================================================

@[extern "lean_sodium_memzero"]
opaque sodium_memzero : ByteArray → IO ByteArray

@[extern "lean_sodium_bin2hex"]
opaque sodium_bin2hex : @&ByteArray → IO (Option String)

@[extern "lean_sodium_hex2bin"]
opaque sodium_hex2bin : @&String → IO (Option ByteArray)

@[extern "lean_sodium_memcmp"]
opaque sodium_memcmp : @&ByteArray → @&ByteArray → IO Bool

-- ============================================================================
-- Constants
-- ============================================================================

@[extern "lean_crypto_secretbox_keybytes"]
opaque crypto_secretbox_keybytes : Unit → UInt32

@[extern "lean_crypto_secretbox_noncebytes"]
opaque crypto_secretbox_noncebytes : Unit → UInt32

@[extern "lean_crypto_secretbox_macbytes"]
opaque crypto_secretbox_macbytes : Unit → UInt32

@[extern "lean_crypto_box_publickeybytes"]
opaque crypto_box_publickeybytes : Unit → UInt32

@[extern "lean_crypto_box_secretkeybytes"]
opaque crypto_box_secretkeybytes : Unit → UInt32

@[extern "lean_crypto_box_noncebytes"]
opaque crypto_box_noncebytes : Unit → UInt32

@[extern "lean_crypto_box_macbytes"]
opaque crypto_box_macbytes : Unit → UInt32

@[extern "lean_crypto_box_sealbytes"]
opaque crypto_box_sealbytes : Unit → UInt32

@[extern "lean_crypto_sign_publickeybytes"]
opaque crypto_sign_publickeybytes : Unit → UInt32

@[extern "lean_crypto_sign_secretkeybytes"]
opaque crypto_sign_secretkeybytes : Unit → UInt32

@[extern "lean_crypto_sign_bytes"]
opaque crypto_sign_bytes : Unit → UInt32

@[extern "lean_crypto_auth_keybytes"]
opaque crypto_auth_keybytes : Unit → UInt32

@[extern "lean_crypto_auth_bytes"]
opaque crypto_auth_bytes : Unit → UInt32

@[extern "lean_crypto_pwhash_saltbytes"]
opaque crypto_pwhash_saltbytes : Unit → UInt32

@[extern "lean_crypto_pwhash_opslimit_interactive"]
opaque crypto_pwhash_opslimit_interactive : Unit → UInt64

@[extern "lean_crypto_pwhash_opslimit_moderate"]
opaque crypto_pwhash_opslimit_moderate : Unit → UInt64

@[extern "lean_crypto_pwhash_opslimit_sensitive"]
opaque crypto_pwhash_opslimit_sensitive : Unit → UInt64

@[extern "lean_crypto_pwhash_memlimit_interactive"]
opaque crypto_pwhash_memlimit_interactive : Unit → USize

@[extern "lean_crypto_pwhash_memlimit_moderate"]
opaque crypto_pwhash_memlimit_moderate : Unit → USize

@[extern "lean_crypto_pwhash_memlimit_sensitive"]
opaque crypto_pwhash_memlimit_sensitive : Unit → USize

@[extern "lean_crypto_generichash_bytes"]
opaque crypto_generichash_bytes : Unit → UInt32

@[extern "lean_crypto_generichash_bytes_min"]
opaque crypto_generichash_bytes_min : Unit → UInt32

@[extern "lean_crypto_generichash_bytes_max"]
opaque crypto_generichash_bytes_max : Unit → UInt32

@[extern "lean_crypto_generichash_keybytes"]
opaque crypto_generichash_keybytes : Unit → UInt32

@[extern "lean_crypto_hash_sha256_bytes"]
opaque crypto_hash_sha256_bytes : Unit → UInt32

@[extern "lean_crypto_hash_sha512_bytes"]
opaque crypto_hash_sha512_bytes : Unit → UInt32

@[extern "lean_crypto_kdf_keybytes"]
opaque crypto_kdf_keybytes : Unit → UInt32

@[extern "lean_crypto_kdf_bytes_min"]
opaque crypto_kdf_bytes_min : Unit → UInt32

@[extern "lean_crypto_kdf_bytes_max"]
opaque crypto_kdf_bytes_max : Unit → UInt32

-- ============================================================================
-- SecretStream (XChaCha20-Poly1305)
-- ============================================================================

/-- Opaque type for secretstream state -/
opaque SecretStreamState : Type

@[extern "lean_crypto_secretstream_keygen"]
opaque crypto_secretstream_keygen : IO ByteArray

@[extern "lean_crypto_secretstream_init_push"]
opaque crypto_secretstream_init_push : @&ByteArray → IO (Option (SecretStreamState × ByteArray))

@[extern "lean_crypto_secretstream_push"]
opaque crypto_secretstream_push : SecretStreamState → @&ByteArray → @&ByteArray → UInt8 → IO (Option ByteArray)

@[extern "lean_crypto_secretstream_init_pull"]
opaque crypto_secretstream_init_pull : @&ByteArray → @&ByteArray → IO (Option SecretStreamState)

@[extern "lean_crypto_secretstream_pull"]
opaque crypto_secretstream_pull : SecretStreamState → @&ByteArray → @&ByteArray → IO (Option (ByteArray × UInt32))

@[extern "lean_crypto_secretstream_rekey"]
opaque crypto_secretstream_rekey : SecretStreamState → IO Unit

@[extern "lean_crypto_secretstream_keybytes"]
opaque crypto_secretstream_keybytes : Unit → UInt32

@[extern "lean_crypto_secretstream_headerbytes"]
opaque crypto_secretstream_headerbytes : Unit → UInt32

@[extern "lean_crypto_secretstream_abytes"]
opaque crypto_secretstream_abytes : Unit → UInt32

@[extern "lean_crypto_secretstream_tag_message"]
opaque crypto_secretstream_tag_message : Unit → UInt8

@[extern "lean_crypto_secretstream_tag_push"]
opaque crypto_secretstream_tag_push : Unit → UInt8

@[extern "lean_crypto_secretstream_tag_rekey"]
opaque crypto_secretstream_tag_rekey : Unit → UInt8

@[extern "lean_crypto_secretstream_tag_final"]
opaque crypto_secretstream_tag_final : Unit → UInt8

-- ============================================================================
-- Key Exchange (X25519 + BLAKE2b)
-- ============================================================================

@[extern "lean_crypto_kx_keypair"]
opaque crypto_kx_keypair : IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_kx_seed_keypair"]
opaque crypto_kx_seed_keypair : @&ByteArray → IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_kx_client_session_keys"]
opaque crypto_kx_client_session_keys : @&ByteArray → @&ByteArray → @&ByteArray → IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_kx_server_session_keys"]
opaque crypto_kx_server_session_keys : @&ByteArray → @&ByteArray → @&ByteArray → IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_kx_publickeybytes"]
opaque crypto_kx_publickeybytes : Unit → UInt32

@[extern "lean_crypto_kx_secretkeybytes"]
opaque crypto_kx_secretkeybytes : Unit → UInt32

@[extern "lean_crypto_kx_seedbytes"]
opaque crypto_kx_seedbytes : Unit → UInt32

@[extern "lean_crypto_kx_sessionkeybytes"]
opaque crypto_kx_sessionkeybytes : Unit → UInt32

-- ============================================================================
-- Streaming/Incremental Hash (BLAKE2b)
-- ============================================================================

/-- Opaque type for generichash streaming state -/
opaque GenericHashState : Type

@[extern "lean_crypto_generichash_init"]
opaque crypto_generichash_init : @&ByteArray → USize → IO (Option (GenericHashState × USize))

@[extern "lean_crypto_generichash_update"]
opaque crypto_generichash_update : GenericHashState → @&ByteArray → IO Bool

@[extern "lean_crypto_generichash_final"]
opaque crypto_generichash_final : GenericHashState → USize → IO (Option ByteArray)

-- ============================================================================
-- Short-Input Hashing (SipHash)
-- ============================================================================

@[extern "lean_crypto_shorthash_keygen"]
opaque crypto_shorthash_keygen : IO ByteArray

@[extern "lean_crypto_shorthash"]
opaque crypto_shorthash : @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_shorthash_bytes"]
opaque crypto_shorthash_bytes : Unit → UInt32

@[extern "lean_crypto_shorthash_keybytes"]
opaque crypto_shorthash_keybytes : Unit → UInt32

-- ============================================================================
-- AEAD XChaCha20-Poly1305-IETF
-- ============================================================================

@[extern "lean_crypto_aead_xchacha20poly1305_keygen"]
opaque crypto_aead_xchacha20poly1305_keygen : IO ByteArray

@[extern "lean_crypto_aead_xchacha20poly1305_encrypt"]
opaque crypto_aead_xchacha20poly1305_encrypt : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_aead_xchacha20poly1305_decrypt"]
opaque crypto_aead_xchacha20poly1305_decrypt : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_aead_xchacha20poly1305_encrypt_detached"]
opaque crypto_aead_xchacha20poly1305_encrypt_detached : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option (ByteArray × ByteArray))

@[extern "lean_crypto_aead_xchacha20poly1305_decrypt_detached"]
opaque crypto_aead_xchacha20poly1305_decrypt_detached : @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → @&ByteArray → IO (Option ByteArray)

@[extern "lean_crypto_aead_xchacha20poly1305_keybytes"]
opaque crypto_aead_xchacha20poly1305_keybytes : Unit → UInt32

@[extern "lean_crypto_aead_xchacha20poly1305_npubbytes"]
opaque crypto_aead_xchacha20poly1305_npubbytes : Unit → UInt32

@[extern "lean_crypto_aead_xchacha20poly1305_abytes"]
opaque crypto_aead_xchacha20poly1305_abytes : Unit → UInt32

end Sodium.FFI
