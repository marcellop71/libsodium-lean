/-
  LibsodiumLean/StreamingHash.lean - Incremental/Streaming Hash using BLAKE2b

  Hash data incrementally without loading it all into memory.
  Useful for hashing large files or streaming data.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init

namespace Sodium.StreamingHash

/-- State for incremental hashing -/
structure State where
  state : FFI.GenericHashState
  outlen : USize

/-- Optional key for keyed hashing -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

namespace Key

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size > 0 && bytes.size.toUInt32 ≤ Constants.generichashKeyBytes then
    some { bytes }
  else if bytes.size == 0 then
    some { bytes := ByteArray.empty }
  else
    none

/-- Generate a random key -/
def generate : IO Key := do
  let bytes ← FFI.randombytes_buf Constants.generichashKeyBytes.toUSize
  return { bytes }

/-- Get the raw bytes of a key -/
def toBytes (key : Key) : ByteArray := key.bytes

/-- Empty key (for unkeyed hashing) -/
def empty : Key := { bytes := ByteArray.empty }

end Key

namespace State

/-- Initialize a streaming hash state.
    - `outlen`: desired hash output length (16-64 bytes, default 32)
    - `key`: optional key for keyed hashing -/
def init (outlen : Nat := Constants.generichashBytes.toNat)
    (key : Key := Key.empty) : IO (Option State) := do
  match ← FFI.crypto_generichash_init key.bytes outlen.toUSize with
  | none => return none
  | some (state, actualOutlen) => return some { state, outlen := actualOutlen }

/-- Update the hash state with more data -/
def update (s : State) (input : ByteArray) : IO Bool :=
  FFI.crypto_generichash_update s.state input

/-- Update the hash state with a string -/
def updateString (s : State) (input : String) : IO Bool :=
  update s input.toUTF8

/-- Finalize and get the hash output.
    Note: After calling final, the state should not be used again. -/
def final (s : State) : IO (Option ByteArray) :=
  FFI.crypto_generichash_final s.state s.outlen

end State

/-- Hash multiple chunks incrementally -/
def hashChunks (chunks : Array ByteArray)
    (outlen : Nat := Constants.generichashBytes.toNat)
    (key : Key := Key.empty) : IO (Option ByteArray) := do
  match ← State.init outlen key with
  | none => return none
  | some state =>
    for chunk in chunks do
      let ok ← state.update chunk
      unless ok do return none
    state.final

/-- Hash a list of strings incrementally -/
def hashStrings (strings : List String)
    (outlen : Nat := Constants.generichashBytes.toNat)
    (key : Key := Key.empty) : IO (Option ByteArray) := do
  match ← State.init outlen key with
  | none => return none
  | some state =>
    for s in strings do
      let ok ← state.updateString s
      unless ok do return none
    state.final

/-- Convenience function to hash data in one call (same as Hash.blake2b) -/
def hash (input : ByteArray)
    (outlen : Nat := Constants.generichashBytes.toNat)
    (key : Key := Key.empty) : IO (Option ByteArray) := do
  match ← State.init outlen key with
  | none => return none
  | some state =>
    let ok ← state.update input
    unless ok do return none
    state.final

/-- Monad for streaming hash operations -/
structure StreamingHashM.Context where
  state : State

abbrev StreamingHashM := ReaderT StreamingHashM.Context IO

namespace StreamingHashM

/-- Run a streaming hash computation -/
def run (outlen : Nat := Constants.generichashBytes.toNat)
    (key : Key := Key.empty)
    (action : StreamingHashM α) : IO (Option α) := do
  match ← State.init outlen key with
  | none => return none
  | some state =>
    let result ← ReaderT.run action { state }
    return some result

/-- Update with more data -/
def update (input : ByteArray) : StreamingHashM Bool := do
  let ctx ← read
  ctx.state.update input

/-- Update with a string -/
def updateString (input : String) : StreamingHashM Bool := do
  let ctx ← read
  ctx.state.updateString input

/-- Finalize and get the hash -/
def final : StreamingHashM (Option ByteArray) := do
  let ctx ← read
  ctx.state.final

end StreamingHashM

end Sodium.StreamingHash
