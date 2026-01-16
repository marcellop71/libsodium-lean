/-
  LibsodiumLean/KeyExchange.lean - Key Exchange using X25519 + BLAKE2b

  Derive shared session keys between two parties for establishing
  secure communication channels. Produces separate rx/tx keys for
  bidirectional encryption.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.KeyExchange

/-- Public key for key exchange -/
structure PublicKey where
  bytes : ByteArray
  deriving Nonempty

/-- Secret key for key exchange -/
structure SecretKey where
  bytes : ByteArray
  deriving Nonempty

/-- Key pair for key exchange -/
structure KeyPair where
  publicKey : PublicKey
  secretKey : SecretKey
  deriving Nonempty

/-- Session keys derived from key exchange -/
structure SessionKeys where
  rx : ByteArray  -- Key for receiving (decryption)
  tx : ByteArray  -- Key for transmitting (encryption)
  deriving Nonempty

/-- Seed for deterministic key generation -/
structure Seed where
  bytes : ByteArray
  deriving Nonempty

namespace PublicKey

/-- Create a public key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option PublicKey :=
  if bytes.size == Constants.kxPublicKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a public key -/
def toBytes (pk : PublicKey) : ByteArray := pk.bytes

/-- Get public key as hex string -/
def toHex (pk : PublicKey) : IO (Option String) :=
  FFI.sodium_bin2hex pk.bytes

/-- Create public key from hex string -/
def fromHex (hex : String) : IO (Option PublicKey) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end PublicKey

namespace SecretKey

/-- Create a secret key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option SecretKey :=
  if bytes.size == Constants.kxSecretKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a secret key -/
def toBytes (sk : SecretKey) : ByteArray := sk.bytes

end SecretKey

namespace Seed

/-- Generate a random seed -/
def generate : IO Seed := do
  let bytes ← Random.bytes Constants.kxSeedBytes.toNat
  return { bytes }

/-- Create a seed from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Seed :=
  if bytes.size == Constants.kxSeedBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a seed -/
def toBytes (seed : Seed) : ByteArray := seed.bytes

end Seed

namespace KeyPair

/-- Generate a new random key pair -/
def generate : IO (Option KeyPair) := do
  match ← FFI.crypto_kx_keypair with
  | none => return none
  | some (pkBytes, skBytes) =>
    match PublicKey.fromBytes pkBytes, SecretKey.fromBytes skBytes with
    | some pk, some sk => return some { publicKey := pk, secretKey := sk }
    | _, _ => return none

/-- Generate a key pair from a seed (deterministic) -/
def fromSeed (seed : Seed) : IO (Option KeyPair) := do
  match ← FFI.crypto_kx_seed_keypair seed.bytes with
  | none => return none
  | some (pkBytes, skBytes) =>
    match PublicKey.fromBytes pkBytes, SecretKey.fromBytes skBytes with
    | some pk, some sk => return some { publicKey := pk, secretKey := sk }
    | _, _ => return none

end KeyPair

namespace SessionKeys

/-- Get the receive key as a ByteArray (for use with SecretBox, etc.) -/
def rxKey (sk : SessionKeys) : ByteArray := sk.rx

/-- Get the transmit key as a ByteArray -/
def txKey (sk : SessionKeys) : ByteArray := sk.tx

end SessionKeys

/-- Derive session keys for the client side.
    The client's tx key matches the server's rx key and vice versa. -/
def clientSessionKeys (clientKeyPair : KeyPair) (serverPublicKey : PublicKey)
    : IO (Option SessionKeys) := do
  match ← FFI.crypto_kx_client_session_keys
      clientKeyPair.publicKey.bytes
      clientKeyPair.secretKey.bytes
      serverPublicKey.bytes with
  | none => return none
  | some (rx, tx) => return some { rx, tx }

/-- Derive session keys for the server side.
    The server's tx key matches the client's rx key and vice versa. -/
def serverSessionKeys (serverKeyPair : KeyPair) (clientPublicKey : PublicKey)
    : IO (Option SessionKeys) := do
  match ← FFI.crypto_kx_server_session_keys
      serverKeyPair.publicKey.bytes
      serverKeyPair.secretKey.bytes
      clientPublicKey.bytes with
  | none => return none
  | some (rx, tx) => return some { rx, tx }

/-- Establish a secure channel between client and server.
    Returns (clientKeys, serverKeys) where each party's tx matches
    the other's rx. -/
def establishChannel (clientKeyPair serverKeyPair : KeyPair)
    : IO (Option (SessionKeys × SessionKeys)) := do
  let clientKeys ← clientSessionKeys clientKeyPair serverKeyPair.publicKey
  let serverKeys ← serverSessionKeys serverKeyPair clientKeyPair.publicKey
  match clientKeys, serverKeys with
  | some ck, some sk => return some (ck, sk)
  | _, _ => return none

end Sodium.KeyExchange
