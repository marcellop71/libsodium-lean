/-
  LibsodiumLean/AEAD.lean - Authenticated Encryption with Associated Data

  Uses XChaCha20-Poly1305-IETF for authenticated encryption where
  headers/metadata need authentication without encryption.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.AEAD

/-- Secret key for AEAD encryption (32 bytes) -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

/-- Nonce for AEAD encryption (24 bytes) -/
structure Nonce where
  bytes : ByteArray
  deriving Nonempty

/-- Authentication tag (16 bytes, for detached mode) -/
structure Tag where
  bytes : ByteArray
  deriving Nonempty

namespace Key

/-- Generate a new random key -/
def generate : IO Key := do
  let bytes ← FFI.crypto_aead_xchacha20poly1305_keygen
  return { bytes }

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size == Constants.aeadKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a key -/
def toBytes (key : Key) : ByteArray := key.bytes

/-- Get key as hex string -/
def toHex (key : Key) : IO (Option String) :=
  FFI.sodium_bin2hex key.bytes

/-- Create key from hex string -/
def fromHex (hex : String) : IO (Option Key) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end Key

namespace Nonce

/-- Generate a new random nonce -/
def generate : IO Nonce := do
  let bytes ← Random.bytes Constants.aeadNonceBytes.toNat
  return { bytes }

/-- Create a nonce from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Nonce :=
  if bytes.size == Constants.aeadNonceBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a nonce -/
def toBytes (nonce : Nonce) : ByteArray := nonce.bytes

end Nonce

namespace Tag

/-- Create a tag from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Tag :=
  if bytes.size == Constants.aeadABytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a tag -/
def toBytes (tag : Tag) : ByteArray := tag.bytes

end Tag

/-- Encrypt a message with associated data.
    The associated data is authenticated but not encrypted. -/
def encrypt (message : ByteArray) (ad : ByteArray) (nonce : Nonce) (key : Key)
    : IO (Option ByteArray) :=
  FFI.crypto_aead_xchacha20poly1305_encrypt message ad nonce.bytes key.bytes

/-- Decrypt a ciphertext and verify the associated data.
    Returns none if authentication fails. -/
def decrypt (ciphertext : ByteArray) (ad : ByteArray) (nonce : Nonce) (key : Key)
    : IO (Option ByteArray) :=
  FFI.crypto_aead_xchacha20poly1305_decrypt ciphertext ad nonce.bytes key.bytes

/-- Encrypt a string message with associated data -/
def encryptString (message : String) (ad : ByteArray) (nonce : Nonce) (key : Key)
    : IO (Option ByteArray) :=
  encrypt message.toUTF8 ad nonce key

/-- Decrypt to a string and verify the associated data -/
def decryptString (ciphertext : ByteArray) (ad : ByteArray) (nonce : Nonce) (key : Key)
    : IO (Option String) := do
  match ← decrypt ciphertext ad nonce key with
  | none => return none
  | some plaintext => return String.fromUTF8? plaintext

/-- Encrypt with automatic nonce generation (returns nonce prepended to ciphertext) -/
def encryptWithNonce (message : ByteArray) (ad : ByteArray) (key : Key)
    : IO (Option ByteArray) := do
  let nonce ← Nonce.generate
  match ← encrypt message ad nonce key with
  | none => return none
  | some ciphertext => return some (nonce.bytes ++ ciphertext)

/-- Decrypt a message that has nonce prepended -/
def decryptWithNonce (combined : ByteArray) (ad : ByteArray) (key : Key)
    : IO (Option ByteArray) := do
  let nonceSize := Constants.aeadNonceBytes.toNat
  if combined.size < nonceSize then
    return none
  let nonceBytes := combined.extract 0 nonceSize
  let ciphertext := combined.extract nonceSize combined.size
  match Nonce.fromBytes nonceBytes with
  | none => return none
  | some nonce => decrypt ciphertext ad nonce key

/-- Detached encryption: returns ciphertext and tag separately -/
def encryptDetached (message : ByteArray) (ad : ByteArray) (nonce : Nonce) (key : Key)
    : IO (Option (ByteArray × Tag)) := do
  match ← FFI.crypto_aead_xchacha20poly1305_encrypt_detached message ad nonce.bytes key.bytes with
  | none => return none
  | some (ciphertext, tagBytes) =>
    match Tag.fromBytes tagBytes with
    | none => return none
    | some tag => return some (ciphertext, tag)

/-- Detached decryption: verify tag and decrypt -/
def decryptDetached (ciphertext : ByteArray) (tag : Tag) (ad : ByteArray)
    (nonce : Nonce) (key : Key) : IO (Option ByteArray) :=
  FFI.crypto_aead_xchacha20poly1305_decrypt_detached ciphertext tag.bytes ad nonce.bytes key.bytes

/-- High-level encryption monad -/
abbrev AEADM := ReaderT Key IO

namespace AEADM

/-- Run an AEADM action with a key -/
def runWith (action : AEADM α) (key : Key) : IO α :=
  ReaderT.run action key

/-- Encrypt in AEADM context -/
def encrypt (message : ByteArray) (ad : ByteArray) (nonce : Nonce) : AEADM (Option ByteArray) := do
  let key ← read
  AEAD.encrypt message ad nonce key

/-- Decrypt in AEADM context -/
def decrypt (ciphertext : ByteArray) (ad : ByteArray) (nonce : Nonce) : AEADM (Option ByteArray) := do
  let key ← read
  AEAD.decrypt ciphertext ad nonce key

/-- Encrypt with automatic nonce -/
def encryptAuto (message : ByteArray) (ad : ByteArray) : AEADM (Option ByteArray) := do
  let key ← read
  AEAD.encryptWithNonce message ad key

/-- Decrypt with prepended nonce -/
def decryptAuto (combined : ByteArray) (ad : ByteArray) : AEADM (Option ByteArray) := do
  let key ← read
  AEAD.decryptWithNonce combined ad key

end AEADM

end Sodium.AEAD
