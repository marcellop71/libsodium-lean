/-
  LibsodiumLean/SecretBox.lean - Secret-key authenticated encryption

  Uses XSalsa20 stream cipher and Poly1305 MAC.
  Suitable for encrypting data when both parties share a secret key.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.SecretBox

/-- Secret key for symmetric encryption -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

/-- Nonce for encryption (must be unique per message) -/
structure Nonce where
  bytes : ByteArray
  deriving Nonempty

namespace Key

/-- Generate a new random key -/
def generate : IO Key := do
  let bytes ← FFI.crypto_secretbox_keygen
  return { bytes }

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size == Constants.secretboxKeyBytes.toNat then
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
  let bytes ← Random.bytes Constants.secretboxNonceBytes.toNat
  return { bytes }

/-- Create a nonce from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Nonce :=
  if bytes.size == Constants.secretboxNonceBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a nonce -/
def toBytes (nonce : Nonce) : ByteArray := nonce.bytes

end Nonce

/-- Encrypt a message with a key and nonce -/
def encrypt (message : ByteArray) (nonce : Nonce) (key : Key) : IO (Option ByteArray) :=
  FFI.crypto_secretbox_easy message nonce.bytes key.bytes

/-- Decrypt a ciphertext with a key and nonce -/
def decrypt (ciphertext : ByteArray) (nonce : Nonce) (key : Key) : IO (Option ByteArray) :=
  FFI.crypto_secretbox_open_easy ciphertext nonce.bytes key.bytes

/-- Encrypt a string message -/
def encryptString (message : String) (nonce : Nonce) (key : Key) : IO (Option ByteArray) :=
  encrypt message.toUTF8 nonce key

/-- Decrypt to a string -/
def decryptString (ciphertext : ByteArray) (nonce : Nonce) (key : Key) : IO (Option String) := do
  match ← decrypt ciphertext nonce key with
  | none => return none
  | some plaintext => return String.fromUTF8? plaintext

/-- Encrypt with automatic nonce generation (returns nonce prepended to ciphertext) -/
def encryptWithNonce (message : ByteArray) (key : Key) : IO (Option ByteArray) := do
  let nonce ← Nonce.generate
  match ← encrypt message nonce key with
  | none => return none
  | some ciphertext => return some (nonce.bytes ++ ciphertext)

/-- Decrypt a message that has nonce prepended -/
def decryptWithNonce (combined : ByteArray) (key : Key) : IO (Option ByteArray) := do
  let nonceSize := Constants.secretboxNonceBytes.toNat
  if combined.size < nonceSize then
    return none
  let nonceBytes := combined.extract 0 nonceSize
  let ciphertext := combined.extract nonceSize combined.size
  match Nonce.fromBytes nonceBytes with
  | none => return none
  | some nonce => decrypt ciphertext nonce key

/-- High-level encryption monad -/
abbrev SecretBoxM := ReaderT Key IO

namespace SecretBoxM

/-- Run a SecretBoxM action with a key -/
def runWith (action : SecretBoxM α) (key : Key) : IO α :=
  ReaderT.run action key

/-- Encrypt in SecretBoxM context -/
def encrypt (message : ByteArray) (nonce : Nonce) : SecretBoxM (Option ByteArray) := do
  let key ← read
  SecretBox.encrypt message nonce key

/-- Decrypt in SecretBoxM context -/
def decrypt (ciphertext : ByteArray) (nonce : Nonce) : SecretBoxM (Option ByteArray) := do
  let key ← read
  SecretBox.decrypt ciphertext nonce key

/-- Encrypt with automatic nonce -/
def encryptAuto (message : ByteArray) : SecretBoxM (Option ByteArray) := do
  let key ← read
  SecretBox.encryptWithNonce message key

/-- Decrypt with prepended nonce -/
def decryptAuto (combined : ByteArray) : SecretBoxM (Option ByteArray) := do
  let key ← read
  SecretBox.decryptWithNonce combined key

end SecretBoxM

end Sodium.SecretBox
