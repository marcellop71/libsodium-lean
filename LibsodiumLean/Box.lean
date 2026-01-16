/-
  LibsodiumLean/Box.lean - Public-key authenticated encryption

  Uses X25519 key exchange, XSalsa20 stream cipher, and Poly1305 MAC.
  Suitable for encrypting data between two parties who know each other's public keys.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.Box

/-- Public key for encryption -/
structure PublicKey where
  bytes : ByteArray
  deriving Nonempty

/-- Secret key for decryption -/
structure SecretKey where
  bytes : ByteArray
  deriving Nonempty

/-- A key pair containing both public and secret keys -/
structure KeyPair where
  publicKey : PublicKey
  secretKey : SecretKey
  deriving Nonempty

/-- Nonce for encryption -/
structure Nonce where
  bytes : ByteArray
  deriving Nonempty

namespace KeyPair

/-- Generate a new random key pair -/
def generate : IO (Option KeyPair) := do
  match ← FFI.crypto_box_keypair with
  | none => return none
  | some (pk, sk) => return some {
      publicKey := { bytes := pk }
      secretKey := { bytes := sk }
    }

end KeyPair

namespace PublicKey

/-- Create a public key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option PublicKey :=
  if bytes.size == Constants.boxPublicKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a public key -/
def toBytes (key : PublicKey) : ByteArray := key.bytes

/-- Get public key as hex string -/
def toHex (key : PublicKey) : IO (Option String) :=
  FFI.sodium_bin2hex key.bytes

/-- Create public key from hex string -/
def fromHex (hex : String) : IO (Option PublicKey) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end PublicKey

namespace SecretKey

/-- Create a secret key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option SecretKey :=
  if bytes.size == Constants.boxSecretKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a secret key -/
def toBytes (key : SecretKey) : ByteArray := key.bytes

end SecretKey

namespace Nonce

/-- Generate a new random nonce -/
def generate : IO Nonce := do
  let bytes ← Random.bytes Constants.boxNonceBytes.toNat
  return { bytes }

/-- Create a nonce from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Nonce :=
  if bytes.size == Constants.boxNonceBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a nonce -/
def toBytes (nonce : Nonce) : ByteArray := nonce.bytes

end Nonce

/-- Encrypt a message to a recipient -/
def encrypt (message : ByteArray) (nonce : Nonce)
            (recipientPk : PublicKey) (senderSk : SecretKey) : IO (Option ByteArray) :=
  FFI.crypto_box_easy message nonce.bytes recipientPk.bytes senderSk.bytes

/-- Decrypt a message from a sender -/
def decrypt (ciphertext : ByteArray) (nonce : Nonce)
            (senderPk : PublicKey) (recipientSk : SecretKey) : IO (Option ByteArray) :=
  FFI.crypto_box_open_easy ciphertext nonce.bytes senderPk.bytes recipientSk.bytes

/-- Encrypt a string message -/
def encryptString (message : String) (nonce : Nonce)
                  (recipientPk : PublicKey) (senderSk : SecretKey) : IO (Option ByteArray) :=
  encrypt message.toUTF8 nonce recipientPk senderSk

/-- Decrypt to a string -/
def decryptString (ciphertext : ByteArray) (nonce : Nonce)
                  (senderPk : PublicKey) (recipientSk : SecretKey) : IO (Option String) := do
  match ← decrypt ciphertext nonce senderPk recipientSk with
  | none => return none
  | some plaintext => return String.fromUTF8? plaintext

-- Sealed box: encrypt anonymously to a recipient
namespace Sealed

/-- Encrypt a message anonymously (no sender authentication) -/
def encrypt (message : ByteArray) (recipientPk : PublicKey) : IO (Option ByteArray) :=
  FFI.crypto_box_seal message recipientPk.bytes

/-- Decrypt an anonymous message -/
def decrypt (ciphertext : ByteArray) (recipientPk : PublicKey)
            (recipientSk : SecretKey) : IO (Option ByteArray) :=
  FFI.crypto_box_seal_open ciphertext recipientPk.bytes recipientSk.bytes

/-- Encrypt a string anonymously -/
def encryptString (message : String) (recipientPk : PublicKey) : IO (Option ByteArray) :=
  encrypt message.toUTF8 recipientPk

/-- Decrypt an anonymous message to string -/
def decryptString (ciphertext : ByteArray) (recipientPk : PublicKey)
                  (recipientSk : SecretKey) : IO (Option String) := do
  match ← decrypt ciphertext recipientPk recipientSk with
  | none => return none
  | some plaintext => return String.fromUTF8? plaintext

end Sealed

/-- Key pair context for encryption/decryption -/
structure BoxContext where
  myKeyPair : KeyPair
  theirPublicKey : PublicKey
  deriving Nonempty

/-- Box monad for convenient encryption operations -/
abbrev BoxM := ReaderT BoxContext IO

namespace BoxM

/-- Run a BoxM action with a context -/
def runWith (action : BoxM α) (ctx : BoxContext) : IO α :=
  ReaderT.run action ctx

/-- Encrypt to the peer -/
def encrypt (message : ByteArray) (nonce : Nonce) : BoxM (Option ByteArray) := do
  let ctx ← read
  Box.encrypt message nonce ctx.theirPublicKey ctx.myKeyPair.secretKey

/-- Decrypt from the peer -/
def decrypt (ciphertext : ByteArray) (nonce : Nonce) : BoxM (Option ByteArray) := do
  let ctx ← read
  Box.decrypt ciphertext nonce ctx.theirPublicKey ctx.myKeyPair.secretKey

end BoxM

end Sodium.Box
