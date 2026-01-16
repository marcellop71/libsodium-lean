/-
  LibsodiumLean/Init.lean - Sodium initialization and constants
-/

import LibsodiumLean.FFI

namespace Sodium

/-- Initialize libsodium. Must be called before using any other function. -/
def init : IO Bool := FFI.sodium_init

/-- Get libsodium version string -/
def version : IO String := FFI.sodium_version

-- Constants for cryptographic sizes
namespace Constants

def secretboxKeyBytes : UInt32 := FFI.crypto_secretbox_keybytes ()
def secretboxNonceBytes : UInt32 := FFI.crypto_secretbox_noncebytes ()
def secretboxMacBytes : UInt32 := FFI.crypto_secretbox_macbytes ()

def boxPublicKeyBytes : UInt32 := FFI.crypto_box_publickeybytes ()
def boxSecretKeyBytes : UInt32 := FFI.crypto_box_secretkeybytes ()
def boxNonceBytes : UInt32 := FFI.crypto_box_noncebytes ()
def boxMacBytes : UInt32 := FFI.crypto_box_macbytes ()
def boxSealBytes : UInt32 := FFI.crypto_box_sealbytes ()

def signPublicKeyBytes : UInt32 := FFI.crypto_sign_publickeybytes ()
def signSecretKeyBytes : UInt32 := FFI.crypto_sign_secretkeybytes ()
def signBytes : UInt32 := FFI.crypto_sign_bytes ()

def authKeyBytes : UInt32 := FFI.crypto_auth_keybytes ()
def authBytes : UInt32 := FFI.crypto_auth_bytes ()

def pwhashSaltBytes : UInt32 := FFI.crypto_pwhash_saltbytes ()
def pwhashOpsLimitInteractive : UInt64 := FFI.crypto_pwhash_opslimit_interactive ()
def pwhashOpsLimitModerate : UInt64 := FFI.crypto_pwhash_opslimit_moderate ()
def pwhashOpsLimitSensitive : UInt64 := FFI.crypto_pwhash_opslimit_sensitive ()
def pwhashMemLimitInteractive : USize := FFI.crypto_pwhash_memlimit_interactive ()
def pwhashMemLimitModerate : USize := FFI.crypto_pwhash_memlimit_moderate ()
def pwhashMemLimitSensitive : USize := FFI.crypto_pwhash_memlimit_sensitive ()

def generichashBytes : UInt32 := FFI.crypto_generichash_bytes ()
def generichashBytesMin : UInt32 := FFI.crypto_generichash_bytes_min ()
def generichashBytesMax : UInt32 := FFI.crypto_generichash_bytes_max ()
def generichashKeyBytes : UInt32 := FFI.crypto_generichash_keybytes ()

def sha256Bytes : UInt32 := FFI.crypto_hash_sha256_bytes ()
def sha512Bytes : UInt32 := FFI.crypto_hash_sha512_bytes ()

def kdfKeyBytes : UInt32 := FFI.crypto_kdf_keybytes ()
def kdfBytesMin : UInt32 := FFI.crypto_kdf_bytes_min ()
def kdfBytesMax : UInt32 := FFI.crypto_kdf_bytes_max ()

-- SecretStream constants
def secretstreamKeyBytes : UInt32 := FFI.crypto_secretstream_keybytes ()
def secretstreamHeaderBytes : UInt32 := FFI.crypto_secretstream_headerbytes ()
def secretstreamABytes : UInt32 := FFI.crypto_secretstream_abytes ()
def secretstreamTagMessage : UInt8 := FFI.crypto_secretstream_tag_message ()
def secretstreamTagPush : UInt8 := FFI.crypto_secretstream_tag_push ()
def secretstreamTagRekey : UInt8 := FFI.crypto_secretstream_tag_rekey ()
def secretstreamTagFinal : UInt8 := FFI.crypto_secretstream_tag_final ()

-- Key Exchange constants
def kxPublicKeyBytes : UInt32 := FFI.crypto_kx_publickeybytes ()
def kxSecretKeyBytes : UInt32 := FFI.crypto_kx_secretkeybytes ()
def kxSeedBytes : UInt32 := FFI.crypto_kx_seedbytes ()
def kxSessionKeyBytes : UInt32 := FFI.crypto_kx_sessionkeybytes ()

-- Short Hash constants
def shorthashBytes : UInt32 := FFI.crypto_shorthash_bytes ()
def shorthashKeyBytes : UInt32 := FFI.crypto_shorthash_keybytes ()

-- AEAD constants
def aeadKeyBytes : UInt32 := FFI.crypto_aead_xchacha20poly1305_keybytes ()
def aeadNonceBytes : UInt32 := FFI.crypto_aead_xchacha20poly1305_npubbytes ()
def aeadABytes : UInt32 := FFI.crypto_aead_xchacha20poly1305_abytes ()

end Constants

end Sodium
