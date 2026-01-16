/-
  LibsodiumLean/Password.lean - Password hashing (Argon2id)

  Uses Argon2id for password hashing, winner of the Password Hashing Competition.
  Suitable for hashing passwords for storage and verification.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.Password

/-- Security level for password hashing -/
inductive SecurityLevel
  | interactive  -- Fast, suitable for interactive login (3 ops, 64 MiB)
  | moderate     -- Balanced (3 ops, 256 MiB)
  | sensitive    -- High security for sensitive data (4 ops, 1 GiB)
  deriving Inhabited, BEq

namespace SecurityLevel

/-- Get ops limit for security level -/
def opsLimit (level : SecurityLevel) : UInt64 :=
  match level with
  | .interactive => Constants.pwhashOpsLimitInteractive
  | .moderate => Constants.pwhashOpsLimitModerate
  | .sensitive => Constants.pwhashOpsLimitSensitive

/-- Get memory limit for security level -/
def memLimit (level : SecurityLevel) : USize :=
  match level with
  | .interactive => Constants.pwhashMemLimitInteractive
  | .moderate => Constants.pwhashMemLimitModerate
  | .sensitive => Constants.pwhashMemLimitSensitive

end SecurityLevel

/-- Salt for password hashing -/
structure Salt where
  bytes : ByteArray
  deriving Nonempty

namespace Salt

/-- Generate a new random salt -/
def generate : IO Salt := do
  let bytes ← Random.bytes Constants.pwhashSaltBytes.toNat
  return { bytes }

/-- Create a salt from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Salt :=
  if bytes.size == Constants.pwhashSaltBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a salt -/
def toBytes (salt : Salt) : ByteArray := salt.bytes

/-- Get salt as hex string -/
def toHex (salt : Salt) : IO (Option String) :=
  FFI.sodium_bin2hex salt.bytes

/-- Create salt from hex string -/
def fromHex (hex : String) : IO (Option Salt) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end Salt

/-- Derive a key from a password -/
def deriveKey (password : ByteArray) (salt : Salt) (keyLength : Nat)
              (level : SecurityLevel := .interactive) : IO (Option ByteArray) :=
  FFI.crypto_pwhash password salt.bytes keyLength.toUSize level.opsLimit level.memLimit

/-- Derive a key from a string password -/
def deriveKeyFromString (password : String) (salt : Salt) (keyLength : Nat)
                        (level : SecurityLevel := .interactive) : IO (Option ByteArray) :=
  deriveKey password.toUTF8 salt keyLength level

/-- Hash a password for storage (includes salt in output) -/
def hashForStorage (password : ByteArray)
                   (level : SecurityLevel := .interactive) : IO (Option String) :=
  FFI.crypto_pwhash_str password level.opsLimit level.memLimit

/-- Hash a string password for storage -/
def hashStringForStorage (password : String)
                         (level : SecurityLevel := .interactive) : IO (Option String) :=
  hashForStorage password.toUTF8 level

/-- Verify a password against a stored hash -/
def verifyStorage (hash : String) (password : ByteArray) : IO Bool :=
  FFI.crypto_pwhash_str_verify hash password

/-- Verify a string password against a stored hash -/
def verifyStringStorage (hash : String) (password : String) : IO Bool :=
  verifyStorage hash password.toUTF8

/-- Check if a stored hash needs rehashing (e.g., security level increased) -/
def needsRehash (_hash : String) (_level : SecurityLevel := .interactive) : Bool :=
  -- Note: libsodium provides crypto_pwhash_str_needs_rehash but we'd need to add it to the shim
  -- For now, return false
  false

end Sodium.Password
