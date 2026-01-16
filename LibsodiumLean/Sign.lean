/-
  LibsodiumLean/Sign.lean - Digital signatures (Ed25519)

  Uses Ed25519 for signing and verification.
  Suitable for signing messages to prove authenticity.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.Sign

/-- Public key for signature verification -/
structure PublicKey where
  bytes : ByteArray
  deriving Nonempty

/-- Secret key for signing -/
structure SecretKey where
  bytes : ByteArray
  deriving Nonempty

/-- A key pair for signing -/
structure KeyPair where
  publicKey : PublicKey
  secretKey : SecretKey
  deriving Nonempty

/-- A detached signature -/
structure Signature where
  bytes : ByteArray
  deriving Nonempty

namespace KeyPair

/-- Generate a new random signing key pair -/
def generate : IO (Option KeyPair) := do
  match ← FFI.crypto_sign_keypair with
  | none => return none
  | some (pk, sk) => return some {
      publicKey := { bytes := pk }
      secretKey := { bytes := sk }
    }

end KeyPair

namespace PublicKey

/-- Create a public key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option PublicKey :=
  if bytes.size == Constants.signPublicKeyBytes.toNat then
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
  if bytes.size == Constants.signSecretKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a secret key -/
def toBytes (key : SecretKey) : ByteArray := key.bytes

end SecretKey

namespace Signature

/-- Create a signature from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Signature :=
  if bytes.size == Constants.signBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a signature -/
def toBytes (sig : Signature) : ByteArray := sig.bytes

/-- Get signature as hex string -/
def toHex (sig : Signature) : IO (Option String) :=
  FFI.sodium_bin2hex sig.bytes

/-- Create signature from hex string -/
def fromHex (hex : String) : IO (Option Signature) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end Signature

/-- Sign a message (detached signature) -/
def sign (message : ByteArray) (secretKey : SecretKey) : IO (Option Signature) := do
  match ← FFI.crypto_sign_detached message secretKey.bytes with
  | none => return none
  | some bytes => return some { bytes }

/-- Sign a string message -/
def signString (message : String) (secretKey : SecretKey) : IO (Option Signature) :=
  sign message.toUTF8 secretKey

/-- Verify a signature -/
def verify (signature : Signature) (message : ByteArray) (publicKey : PublicKey) : IO Bool :=
  FFI.crypto_sign_verify_detached signature.bytes message publicKey.bytes

/-- Verify a signature for a string message -/
def verifyString (signature : Signature) (message : String) (publicKey : PublicKey) : IO Bool :=
  verify signature message.toUTF8 publicKey

/-- Signer monad for convenient signing operations -/
abbrev SignerM := ReaderT SecretKey IO

namespace SignerM

/-- Run a SignerM action with a secret key -/
def runWith (action : SignerM α) (sk : SecretKey) : IO α :=
  ReaderT.run action sk

/-- Run with a key pair (uses secret key) -/
def runWithKeyPair (action : SignerM α) (kp : KeyPair) : IO α :=
  ReaderT.run action kp.secretKey

/-- Sign a message in SignerM context -/
def sign (message : ByteArray) : SignerM (Option Signature) := do
  let sk ← read
  Sign.sign message sk

/-- Sign a string in SignerM context -/
def signString (message : String) : SignerM (Option Signature) := do
  let sk ← read
  Sign.signString message sk

end SignerM

/-- Verifier monad for convenient verification operations -/
abbrev VerifierM := ReaderT PublicKey IO

namespace VerifierM

/-- Run a VerifierM action with a public key -/
def runWith (action : VerifierM α) (pk : PublicKey) : IO α :=
  ReaderT.run action pk

/-- Run with a key pair (uses public key) -/
def runWithKeyPair (action : VerifierM α) (kp : KeyPair) : IO α :=
  ReaderT.run action kp.publicKey

/-- Verify a signature in VerifierM context -/
def verify (signature : Signature) (message : ByteArray) : VerifierM Bool := do
  let pk ← read
  Sign.verify signature message pk

/-- Verify a string signature in VerifierM context -/
def verifyString (signature : Signature) (message : String) : VerifierM Bool := do
  let pk ← read
  Sign.verifyString signature message pk

end VerifierM

end Sodium.Sign
