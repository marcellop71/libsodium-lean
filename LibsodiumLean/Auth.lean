/-
  LibsodiumLean/Auth.lean - Message authentication codes

  Uses HMAC-SHA512-256 for authentication.
  Suitable for verifying message integrity when both parties share a secret key.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.Auth

/-- Secret key for message authentication -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

/-- Authentication tag -/
structure Tag where
  bytes : ByteArray
  deriving Nonempty

namespace Key

/-- Generate a new random authentication key -/
def generate : IO Key := do
  let bytes ← FFI.crypto_auth_keygen
  return { bytes }

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size == Constants.authKeyBytes.toNat then
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

namespace Tag

/-- Create a tag from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Tag :=
  if bytes.size == Constants.authBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a tag -/
def toBytes (tag : Tag) : ByteArray := tag.bytes

/-- Get tag as hex string -/
def toHex (tag : Tag) : IO (Option String) :=
  FFI.sodium_bin2hex tag.bytes

/-- Create tag from hex string -/
def fromHex (hex : String) : IO (Option Tag) := do
  match ← FFI.sodium_hex2bin hex with
  | none => return none
  | some bytes => return fromBytes bytes

end Tag

/-- Compute authentication tag for a message -/
def authenticate (message : ByteArray) (key : Key) : IO (Option Tag) := do
  match ← FFI.crypto_auth message key.bytes with
  | none => return none
  | some bytes => return some { bytes }

/-- Authenticate a string message -/
def authenticateString (message : String) (key : Key) : IO (Option Tag) :=
  authenticate message.toUTF8 key

/-- Verify an authentication tag -/
def verify (tag : Tag) (message : ByteArray) (key : Key) : IO Bool :=
  FFI.crypto_auth_verify tag.bytes message key.bytes

/-- Verify an authentication tag for a string message -/
def verifyString (tag : Tag) (message : String) (key : Key) : IO Bool :=
  verify tag message.toUTF8 key

/-- Auth monad for convenient authentication operations -/
abbrev AuthM := ReaderT Key IO

namespace AuthM

/-- Run an AuthM action with a key -/
def runWith (action : AuthM α) (key : Key) : IO α :=
  ReaderT.run action key

/-- Authenticate a message in AuthM context -/
def authenticate (message : ByteArray) : AuthM (Option Tag) := do
  let key ← read
  Auth.authenticate message key

/-- Authenticate a string in AuthM context -/
def authenticateString (message : String) : AuthM (Option Tag) := do
  let key ← read
  Auth.authenticateString message key

/-- Verify a tag in AuthM context -/
def verify (tag : Tag) (message : ByteArray) : AuthM Bool := do
  let key ← read
  Auth.verify tag message key

/-- Verify a string tag in AuthM context -/
def verifyString (tag : Tag) (message : String) : AuthM Bool := do
  let key ← read
  Auth.verifyString tag message key

end AuthM

end Sodium.Auth
