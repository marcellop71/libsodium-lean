/-
  LibsodiumLean/Utils.lean - Utility functions

  Hex encoding, secure comparison, memory zeroing, etc.
-/

import LibsodiumLean.FFI

namespace Sodium.Utils

/-- Convert binary data to hex string -/
def toHex (data : ByteArray) : IO (Option String) :=
  FFI.sodium_bin2hex data

/-- Convert hex string to binary data -/
def fromHex (hex : String) : IO (Option ByteArray) :=
  FFI.sodium_hex2bin hex

/-- Constant-time comparison of two byte arrays -/
def secureCompare (a : ByteArray) (b : ByteArray) : IO Bool :=
  FFI.sodium_memcmp a b

/-- Zero out memory (for sensitive data) -/
def memzero (data : ByteArray) : IO ByteArray :=
  FFI.sodium_memzero data

/-- Pad data to a multiple of blockSize -/
def pad (data : ByteArray) (blockSize : Nat) : ByteArray :=
  let remainder := data.size % blockSize
  if remainder == 0 then data
  else
    let padding := blockSize - remainder
    let zeros := ByteArray.mk (Array.replicate padding 0)
    data ++ zeros

/-- Remove PKCS7-style padding -/
def unpad (data : ByteArray) : Option ByteArray :=
  if data.size == 0 then none
  else
    let lastByte := data.get! (data.size - 1)
    let padLen := lastByte.toNat
    if padLen == 0 || padLen > data.size then none
    else some (data.extract 0 (data.size - padLen))

/-- Increment a nonce (for counter mode) -/
def incrementNonce (nonce : ByteArray) : ByteArray := Id.run do
  let mut result := ByteArray.mk (Array.replicate nonce.size 0)
  result := nonce.copySlice 0 result 0 nonce.size
  let mut carry : UInt8 := 1
  for i in [:nonce.size] do
    let sum := result.get! i + carry
    result := result.set! i sum
    carry := if sum < result.get! i || (carry == 1 && sum == 0) then 1 else 0
    if carry == 0 then break
  result

/-- Compare two byte arrays for equality (not constant-time, use secureCompare for secrets) -/
def bytesEqual (a : ByteArray) (b : ByteArray) : Bool :=
  a.data == b.data

/-- XOR two byte arrays -/
def xor (a : ByteArray) (b : ByteArray) : ByteArray := Id.run do
  let len := min a.size b.size
  let mut result := ByteArray.mk (Array.replicate len 0)
  for i in [:len] do
    result := result.set! i (a.get! i ^^^ b.get! i)
  return result

end Sodium.Utils
