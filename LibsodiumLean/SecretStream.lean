/-
  LibsodiumLean/SecretStream.lean - Encrypted streaming using XChaCha20-Poly1305

  Provides chunked authenticated encryption for streams and large files
  without loading everything into memory. Supports message tags for
  framing (MESSAGE, FINAL, PUSH) and rekeying.
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random

namespace Sodium.SecretStream

/-- Message tag indicating the type of chunk -/
inductive Tag where
  | message  -- Regular message chunk
  | push     -- End of a set of messages (but not final)
  | rekey    -- Explicit rekeying
  | final    -- Final chunk - stream is complete
  deriving Repr, BEq

namespace Tag

def toUInt8 : Tag → UInt8
  | message => Constants.secretstreamTagMessage
  | push => Constants.secretstreamTagPush
  | rekey => Constants.secretstreamTagRekey
  | final => Constants.secretstreamTagFinal

def fromUInt32 (n : UInt32) : Tag :=
  if n == Constants.secretstreamTagMessage.toUInt32 then message
  else if n == Constants.secretstreamTagPush.toUInt32 then push
  else if n == Constants.secretstreamTagRekey.toUInt32 then rekey
  else if n == Constants.secretstreamTagFinal.toUInt32 then final
  else message  -- default to message

end Tag

/-- Secret key for stream encryption -/
structure Key where
  bytes : ByteArray
  deriving Nonempty

/-- Header for initializing decryption -/
structure Header where
  bytes : ByteArray
  deriving Nonempty

/-- Push state for encryption -/
structure PushState where
  state : FFI.SecretStreamState

/-- Pull state for decryption -/
structure PullState where
  state : FFI.SecretStreamState

namespace Key

/-- Generate a new random key -/
def generate : IO Key := do
  let bytes ← FFI.crypto_secretstream_keygen
  return { bytes }

/-- Create a key from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Key :=
  if bytes.size == Constants.secretstreamKeyBytes.toNat then
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

namespace Header

/-- Create a header from raw bytes -/
def fromBytes (bytes : ByteArray) : Option Header :=
  if bytes.size == Constants.secretstreamHeaderBytes.toNat then
    some { bytes }
  else
    none

/-- Get the raw bytes of a header -/
def toBytes (header : Header) : ByteArray := header.bytes

end Header

namespace PushState

/-- Initialize a push (encryption) stream with a key.
    Returns the state and header needed for decryption. -/
def init (key : Key) : IO (Option (PushState × Header)) := do
  match ← FFI.crypto_secretstream_init_push key.bytes with
  | none => return none
  | some (state, headerBytes) =>
    match Header.fromBytes headerBytes with
    | none => return none
    | some header => return some ({ state }, header)

/-- Push a message chunk to the stream.
    Returns the ciphertext for this chunk. -/
def push (ps : PushState) (message : ByteArray) (tag : Tag := .message)
    (ad : ByteArray := ByteArray.empty) : IO (Option ByteArray) :=
  FFI.crypto_secretstream_push ps.state message ad tag.toUInt8

/-- Push a string message chunk -/
def pushString (ps : PushState) (message : String) (tag : Tag := .message)
    (ad : ByteArray := ByteArray.empty) : IO (Option ByteArray) :=
  push ps message.toUTF8 tag ad

/-- Push the final chunk and close the stream -/
def pushFinal (ps : PushState) (message : ByteArray)
    (ad : ByteArray := ByteArray.empty) : IO (Option ByteArray) :=
  push ps message .final ad

/-- Explicitly rekey the stream -/
def rekey (ps : PushState) : IO Unit :=
  FFI.crypto_secretstream_rekey ps.state

end PushState

namespace PullState

/-- Initialize a pull (decryption) stream with a key and header. -/
def init (header : Header) (key : Key) : IO (Option PullState) := do
  match ← FFI.crypto_secretstream_init_pull header.bytes key.bytes with
  | none => return none
  | some state => return some { state }

/-- Pull and decrypt a message chunk from the stream.
    Returns the plaintext and the tag for this chunk. -/
def pull (ps : PullState) (ciphertext : ByteArray)
    (ad : ByteArray := ByteArray.empty) : IO (Option (ByteArray × Tag)) := do
  match ← FFI.crypto_secretstream_pull ps.state ciphertext ad with
  | none => return none
  | some (message, tagNum) => return some (message, Tag.fromUInt32 tagNum)

/-- Pull and decrypt to a string -/
def pullString (ps : PullState) (ciphertext : ByteArray)
    (ad : ByteArray := ByteArray.empty) : IO (Option (String × Tag)) := do
  match ← pull ps ciphertext ad with
  | none => return none
  | some (message, tag) =>
    match String.fromUTF8? message with
    | none => return none
    | some s => return some (s, tag)

/-- Explicitly rekey the stream -/
def rekey (ps : PullState) : IO Unit :=
  FFI.crypto_secretstream_rekey ps.state

end PullState

/-- Encrypt multiple chunks at once, returning header + all ciphertexts -/
def encryptChunks (key : Key) (chunks : Array ByteArray)
    (ad : ByteArray := ByteArray.empty) : IO (Option (Header × Array ByteArray)) := do
  match ← PushState.init key with
  | none => return none
  | some (ps, header) =>
    let mut ciphertexts := Array.empty
    for i in [:chunks.size] do
      let isLast := i == chunks.size - 1
      let tag := if isLast then Tag.final else Tag.message
      match ← ps.push chunks[i]! tag ad with
      | none => return none
      | some ct => ciphertexts := ciphertexts.push ct
    return some (header, ciphertexts)

/-- Decrypt multiple chunks at once -/
def decryptChunks (key : Key) (header : Header) (ciphertexts : Array ByteArray)
    (ad : ByteArray := ByteArray.empty) : IO (Option (Array ByteArray)) := do
  match ← PullState.init header key with
  | none => return none
  | some ps =>
    let mut plaintexts := Array.empty
    for ct in ciphertexts do
      match ← ps.pull ct ad with
      | none => return none
      | some (pt, _tag) => plaintexts := plaintexts.push pt
    return some plaintexts

/-- High-level encryption monad for streaming -/
abbrev SecretStreamM := ReaderT Key IO

namespace SecretStreamM

/-- Run a SecretStreamM action with a key -/
def runWith (action : SecretStreamM α) (key : Key) : IO α :=
  ReaderT.run action key

/-- Create a push state for encryption -/
def initPush : SecretStreamM (Option (PushState × Header)) := do
  let key ← read
  PushState.init key

/-- Create a pull state for decryption -/
def initPull (header : Header) : SecretStreamM (Option PullState) := do
  let key ← read
  PullState.init header key

end SecretStreamM

end Sodium.SecretStream
