/-
  LibsodiumLean/KDF.lean - Key derivation functions

  Derives multiple subkeys from a single master key.
  Useful for creating multiple keys for different purposes from one root key.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.KDF

/-- Master key for key derivation -/
structure MasterKey where
  bytes : ByteArray
  deriving Nonempty

/-- Context string for key derivation (max 8 characters) -/
structure Context where
  value : String
  deriving Nonempty

namespace MasterKey

/-- Generate a new random master key -/
def generate : IO MasterKey := do
  let bytes ← FFI.crypto_kdf_keygen
  return { bytes }

/-- Create a master key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option MasterKey :=
  if bytes.size == Constants.kdfKeyBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a master key -/
def toBytes (key : MasterKey) : ByteArray := key.bytes

/-- Get master key as hex string -/
def toHex (key : MasterKey) : IO (Option String) :=
  FFI.sodium_bin2hex key.bytes

/-- Create master key from hex string -/
def fromHex (hex : String) : IO (Option MasterKey) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end MasterKey

namespace Context

/-- Create a context (will be padded/truncated to 8 chars) -/
def make (s : String) : Context :=
  let truncated := s.toList.take 8
  let paddingLen := 8 - truncated.length
  let padded := truncated ++ List.replicate paddingLen ' '
  { value := String.ofList padded }

/-- Common contexts -/
def encryption : Context := make "encrypt"
def authentication : Context := make "auth"
def signing : Context := make "signing"
def storage : Context := make "storage"

end Context

/-- Derive a subkey from a master key -/
def deriveSubkey (masterKey : MasterKey) (subkeyId : UInt64) (context : Context)
                 (subkeyLength : Nat := 32) : IO (Option ByteArray) := do
  if subkeyLength < Constants.kdfBytesMin.toNat || subkeyLength > Constants.kdfBytesMax.toNat then
    return none
  FFI.crypto_kdf_derive_from_key subkeyLength.toUSize subkeyId context.value masterKey.bytes

/-- Derive multiple subkeys -/
def deriveSubkeys (masterKey : MasterKey) (context : Context)
                  (count : Nat) (subkeyLength : Nat := 32) : IO (Array ByteArray) := do
  let mut keys := #[]
  for i in [:count] do
    match ← deriveSubkey masterKey i.toUInt64 context subkeyLength with
    | none => pure ()
    | some key => keys := keys.push key
  return keys

/-- KDF monad for convenient key derivation -/
abbrev KDFM := ReaderT MasterKey IO

namespace KDFM

/-- Run a KDFM action with a master key -/
def runWith (action : KDFM α) (key : MasterKey) : IO α :=
  ReaderT.run action key

/-- Derive a subkey in KDFM context -/
def deriveSubkey (subkeyId : UInt64) (context : Context)
                 (subkeyLength : Nat := 32) : KDFM (Option ByteArray) := do
  let mk ← read
  KDF.deriveSubkey mk subkeyId context subkeyLength

/-- Derive multiple subkeys in KDFM context -/
def deriveSubkeys (context : Context) (count : Nat)
                  (subkeyLength : Nat := 32) : KDFM (Array ByteArray) := do
  let mk ← read
  KDF.deriveSubkeys mk context count subkeyLength

end KDFM

end Sodium.KDF
