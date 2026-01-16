/-
  LibsodiumLean/Hash.lean - Cryptographic hash functions
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.Hash

-- BLAKE2b hash (generic hash)
namespace Blake2b

/-- Hash data using BLAKE2b with default output length (32 bytes) -/
def hash (data : ByteArray) : IO (Option ByteArray) :=
  FFI.crypto_generichash data ByteArray.empty Constants.generichashBytes.toUSize

/-- Hash data using BLAKE2b with custom output length -/
def hashWithLength (data : ByteArray) (outLen : Nat) : IO (Option ByteArray) :=
  FFI.crypto_generichash data ByteArray.empty outLen.toUSize

/-- Hash data using BLAKE2b with a key -/
def hashKeyed (data : ByteArray) (key : ByteArray) : IO (Option ByteArray) :=
  FFI.crypto_generichash data key Constants.generichashBytes.toUSize

/-- Hash data using BLAKE2b with a key and custom output length -/
def hashKeyedWithLength (data : ByteArray) (key : ByteArray) (outLen : Nat) : IO (Option ByteArray) :=
  FFI.crypto_generichash data key outLen.toUSize

/-- Hash a string using BLAKE2b -/
def hashString (s : String) : IO (Option ByteArray) :=
  hash s.toUTF8

end Blake2b

-- SHA-256 hash
namespace SHA256

/-- Hash data using SHA-256 -/
def hash (data : ByteArray) : IO (Option ByteArray) :=
  FFI.crypto_hash_sha256 data

/-- Hash a string using SHA-256 -/
def hashString (s : String) : IO (Option ByteArray) :=
  hash s.toUTF8

end SHA256

-- SHA-512 hash
namespace SHA512

/-- Hash data using SHA-512 -/
def hash (data : ByteArray) : IO (Option ByteArray) :=
  FFI.crypto_hash_sha512 data

/-- Hash a string using SHA-512 -/
def hashString (s : String) : IO (Option ByteArray) :=
  hash s.toUTF8

end SHA512

/-- Convenience aliases -/
abbrev blake2b := Blake2b.hash
abbrev sha256 := SHA256.hash
abbrev sha512 := SHA512.hash

end Sodium.Hash
