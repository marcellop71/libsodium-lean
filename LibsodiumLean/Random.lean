/-
  LibsodiumLean/Random.lean - Cryptographically secure random number generation
-/

import LibsodiumLean.FFI

namespace Sodium.Random

/-- Generate a random 32-bit unsigned integer -/
def uint32 : IO UInt32 := FFI.randombytes_random

/-- Generate a random integer uniformly distributed in [0, upperBound) -/
def uniform (upperBound : UInt32) : IO UInt32 := FFI.randombytes_uniform upperBound

/-- Generate random bytes -/
def bytes (size : Nat) : IO ByteArray := FFI.randombytes_buf size.toUSize

/-- Generate a random nonce of the given size -/
def nonce (size : Nat) : IO ByteArray := bytes size

/-- Generate a random key of the given size -/
def key (size : Nat) : IO ByteArray := bytes size

/-- Generate a random salt for password hashing -/
def salt : IO ByteArray := bytes 16

/-- Fill a mutable buffer with random bytes -/
def fill (size : Nat) : IO ByteArray := bytes size

/-- Generate random bytes as a hex string -/
def hexString (size : Nat) : IO (Option String) := do
  let buf ← bytes size
  FFI.sodium_bin2hex buf

end Sodium.Random
