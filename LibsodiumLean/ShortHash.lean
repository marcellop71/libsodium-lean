/-
  LibsodiumLean/ShortHash.lean - Short-Input Hashing using SipHash-2-4

  Keyed hash function optimized for short inputs. Prevents HashDoS attacks
  by using a keyed hash for hash table construction.

  Note: Output is only 64 bits (8 bytes) - NOT collision resistant for
  general cryptographic hashing. Use Hash.blake2b for that.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.ShortHash

/-- Key for short hashing (16 bytes) -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

/-- Hash output (8 bytes / 64 bits) -/
structure Hash where
  bytes : ByteArray
  deriving Nonempty

namespace Key

/-- Generate a new random key -/
def generate : IO Key := do
  let bytes ← FFI.crypto_shorthash_keygen
  return { bytes }

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size == Constants.shorthashKeyBytes.toNat then
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

namespace Hash

/-- Create a hash from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Hash :=
  if bytes.size == Constants.shorthashBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a hash -/
def toBytes (h : Hash) : ByteArray := h.bytes

/-- Get hash as hex string -/
def toHex (h : Hash) : IO (Option String) :=
  FFI.sodium_bin2hex h.bytes

/-- Convert hash to UInt64 for use as hash table key -/
def toUInt64 (h : Hash) : UInt64 :=
  let b := h.bytes
  if b.size >= 8 then
    (b[0]!.toUInt64) ||| (b[1]!.toUInt64 <<< 8) |||
    (b[2]!.toUInt64 <<< 16) ||| (b[3]!.toUInt64 <<< 24) |||
    (b[4]!.toUInt64 <<< 32) ||| (b[5]!.toUInt64 <<< 40) |||
    (b[6]!.toUInt64 <<< 48) ||| (b[7]!.toUInt64 <<< 56)
  else
    0

end Hash

/-- Compute a short hash of the input -/
def hash (input : ByteArray) (key : Key) : IO (Option Hash) := do
  match ← FFI.crypto_shorthash input key.bytes with
  | none => return none
  | some bytes => return Hash.fromBytes bytes

/-- Compute a short hash of a string -/
def hashString (input : String) (key : Key) : IO (Option Hash) :=
  hash input.toUTF8 key

/-- Compute a short hash and return as UInt64 -/
def hashToUInt64 (input : ByteArray) (key : Key) : IO (Option UInt64) := do
  match ← hash input key with
  | none => return none
  | some h => return some h.toUInt64

/-- Compute a short hash of a string and return as UInt64 -/
def hashStringToUInt64 (input : String) (key : Key) : IO (Option UInt64) :=
  hashToUInt64 input.toUTF8 key

/-- High-level monad for keyed short hashing -/
abbrev ShortHashM := ReaderT Key IO

namespace ShortHashM

/-- Run a ShortHashM action with a key -/
def runWith (action : ShortHashM α) (key : Key) : IO α :=
  ReaderT.run action key

/-- Hash in ShortHashM context -/
def hash (input : ByteArray) : ShortHashM (Option Hash) := do
  let key ← read
  ShortHash.hash input key

/-- Hash a string in ShortHashM context -/
def hashString (input : String) : ShortHashM (Option Hash) := do
  let key ← read
  ShortHash.hashString input key

/-- Hash to UInt64 in ShortHashM context -/
def hashToUInt64 (input : ByteArray) : ShortHashM (Option UInt64) := do
  let key ← read
  ShortHash.hashToUInt64 input key

end ShortHashM

end Sodium.ShortHash
