/-
  Examples/Main.lean - Example usage of LibsodiumLean
-/

import LibsodiumLean
import ZlogLean

open Sodium

def main : IO Unit := do
  -- Initialize zlog
  let configPath := "config/zlog.conf"
  let logOk ← Zlog.init configPath
  unless logOk do
    IO.eprintln s!"Failed to initialize zlog from '{configPath}'"
    return

  let _ ← Zlog.Default.setCategory "sodium"

  -- Initialize libsodium
  let ok ← Sodium.init
  unless ok do
    Zlog.error "Failed to initialize libsodium"
    Zlog.fini
    return

  let ver ← Sodium.version
  Zlog.info s!"libsodium version: {ver}"

  -- ============================================================
  -- Random number generation
  -- ============================================================
  Zlog.info "=== Random Number Generation ==="

  let r1 ← Random.uint32
  Zlog.debug s!"Random UInt32: {r1}"

  let r2 ← Random.uniform 100
  Zlog.debug s!"Random [0, 100): {r2}"

  let randomBytes ← Random.bytes 16
  match ← Utils.toHex randomBytes with
  | some hex => Zlog.debug s!"Random 16 bytes: {hex}"
  | none => Zlog.warn "Failed to convert to hex"

  -- ============================================================
  -- Hashing
  -- ============================================================
  Zlog.info "=== Hashing ==="

  let message := "Hello, libsodium!".toUTF8

  match ← Hash.blake2b message with
  | some h =>
    match ← Utils.toHex h with
    | some hex => Zlog.debug s!"BLAKE2b: {hex}"
    | none => pure ()
  | none => Zlog.error "BLAKE2b failed"

  match ← Hash.sha256 message with
  | some h =>
    match ← Utils.toHex h with
    | some hex => Zlog.debug s!"SHA-256: {hex}"
    | none => pure ()
  | none => Zlog.error "SHA-256 failed"

  match ← Hash.sha512 message with
  | some h =>
    match ← Utils.toHex h with
    | some hex => Zlog.debug s!"SHA-512: {hex}"
    | none => pure ()
  | none => Zlog.error "SHA-512 failed"

  -- ============================================================
  -- Secret-key encryption (secretbox)
  -- ============================================================
  Zlog.info "=== Secret-key Encryption ==="

  let key ← SecretBox.Key.generate
  let nonce ← SecretBox.Nonce.generate
  let plaintext := "Secret message".toUTF8

  match ← SecretBox.encrypt plaintext nonce key with
  | some ciphertext =>
    Zlog.debug s!"Encrypted ({ciphertext.size} bytes)"
    match ← SecretBox.decrypt ciphertext nonce key with
    | some decrypted =>
      match String.fromUTF8? decrypted with
      | some s => Zlog.debug s!"Decrypted: {s}"
      | none => Zlog.warn "Invalid UTF-8"
    | none => Zlog.error "Decryption failed"
  | none => Zlog.error "Encryption failed"

  -- ============================================================
  -- Public-key encryption (box)
  -- ============================================================
  Zlog.info "=== Public-key Encryption ==="

  match ← Box.KeyPair.generate, ← Box.KeyPair.generate with
  | some alice, some bob =>
    let boxNonce ← Box.Nonce.generate
    let secretMsg := "Hello Bob!".toUTF8

    -- Alice encrypts to Bob
    match ← Box.encrypt secretMsg boxNonce bob.publicKey alice.secretKey with
    | some encrypted =>
      Zlog.debug s!"Alice encrypted ({encrypted.size} bytes)"
      -- Bob decrypts from Alice
      match ← Box.decrypt encrypted boxNonce alice.publicKey bob.secretKey with
      | some decrypted =>
        match String.fromUTF8? decrypted with
        | some s => Zlog.debug s!"Bob decrypted: {s}"
        | none => Zlog.warn "Invalid UTF-8"
      | none => Zlog.error "Bob failed to decrypt"
    | none => Zlog.error "Alice failed to encrypt"
  | _, _ => Zlog.error "Key generation failed"

  -- ============================================================
  -- Sealed boxes (anonymous encryption)
  -- ============================================================
  Zlog.info "=== Sealed Box (Anonymous Encryption) ==="

  match ← Box.KeyPair.generate with
  | some recipient =>
    let anonMsg := "Anonymous message".toUTF8
    match ← Box.Sealed.encrypt anonMsg recipient.publicKey with
    | some sealed =>
      Zlog.debug s!"Sealed ({sealed.size} bytes)"
      match ← Box.Sealed.decrypt sealed recipient.publicKey recipient.secretKey with
      | some opened =>
        match String.fromUTF8? opened with
        | some s => Zlog.debug s!"Opened: {s}"
        | none => Zlog.warn "Invalid UTF-8"
      | none => Zlog.error "Failed to open"
    | none => Zlog.error "Failed to seal"
  | none => Zlog.error "Key generation failed"

  -- ============================================================
  -- Digital signatures
  -- ============================================================
  Zlog.info "=== Digital Signatures ==="

  match ← Sign.KeyPair.generate with
  | some signingKey =>
    let doc := "Important document".toUTF8
    match ← Sign.sign doc signingKey.secretKey with
    | some signature =>
      match ← Utils.toHex signature.bytes with
      | some hex => Zlog.debug s!"Signature: {hex.toList.take 32}..."
      | none => pure ()
      let valid ← Sign.verify signature doc signingKey.publicKey
      Zlog.debug s!"Signature valid: {valid}"
    | none => Zlog.error "Signing failed"
  | none => Zlog.error "Key generation failed"

  -- ============================================================
  -- Message authentication
  -- ============================================================
  Zlog.info "=== Message Authentication ==="

  let authKey ← Auth.Key.generate
  let authMsg := "Authenticated message".toUTF8

  match ← Auth.authenticate authMsg authKey with
  | some tag =>
    match ← Utils.toHex tag.bytes with
    | some hex => Zlog.debug s!"Auth tag: {hex}"
    | none => pure ()
    let authValid ← Auth.verify tag authMsg authKey
    Zlog.debug s!"Tag valid: {authValid}"
  | none => Zlog.error "Authentication failed"

  -- ============================================================
  -- Password hashing
  -- ============================================================
  Zlog.info "=== Password Hashing ==="

  let password := "correct horse battery staple"

  -- Hash for storage
  match ← Password.hashStringForStorage password .interactive with
  | some hash =>
    Zlog.debug s!"Password hash: {hash}"
    let valid ← Password.verifyStringStorage hash password
    Zlog.debug s!"Password valid: {valid}"
    let invalid ← Password.verifyStringStorage hash "wrong password"
    Zlog.debug s!"Wrong password valid: {invalid}"
  | none => Zlog.error "Password hashing failed"

  -- ============================================================
  -- Key derivation
  -- ============================================================
  Zlog.info "=== Key Derivation ==="

  let masterKey ← KDF.MasterKey.generate
  let ctx := KDF.Context.make "example"

  for i in [:3] do
    match ← KDF.deriveSubkey masterKey i.toUInt64 ctx 32 with
    | some subkey =>
      match ← Utils.toHex subkey with
      | some hex => Zlog.debug s!"Subkey {i}: {hex}"
      | none => pure ()
    | none => Zlog.error s!"Failed to derive subkey {i}"

  -- ============================================================
  -- Secret Stream (chunked encryption)
  -- ============================================================
  Zlog.info "=== Secret Stream ==="

  let streamKey ← SecretStream.Key.generate
  match ← SecretStream.PushState.init streamKey with
  | some (pushState, header) =>
    Zlog.debug s!"Stream initialized, header: {header.bytes.size} bytes"
    let chunks := #["Hello ".toUTF8, "World ".toUTF8, "Stream!".toUTF8]
    let mut ciphertexts : Array ByteArray := Array.empty
    for i in [:chunks.size] do
      let isLast := i == chunks.size - 1
      let tag := if isLast then SecretStream.Tag.final else SecretStream.Tag.message
      match ← pushState.push chunks[i]! tag with
      | some ct => ciphertexts := ciphertexts.push ct
      | none => Zlog.error s!"Failed to encrypt chunk {i}"
    Zlog.debug s!"Encrypted {ciphertexts.size} chunks"

    -- Decrypt
    match ← SecretStream.PullState.init header streamKey with
    | some pullState =>
      for i in [:ciphertexts.size] do
        match ← pullState.pull ciphertexts[i]! with
        | some (plaintext, tag) =>
          match String.fromUTF8? plaintext with
          | some s => Zlog.debug s!"Chunk {i}: '{s}' (tag: {repr tag})"
          | none => Zlog.warn "Invalid UTF-8"
        | none => Zlog.error s!"Failed to decrypt chunk {i}"
    | none => Zlog.error "Failed to init pull state"
  | none => Zlog.error "Failed to init push state"

  -- ============================================================
  -- Key Exchange
  -- ============================================================
  Zlog.info "=== Key Exchange ==="

  match ← KeyExchange.KeyPair.generate, ← KeyExchange.KeyPair.generate with
  | some clientKp, some serverKp =>
    Zlog.debug "Generated client and server key pairs"
    match ← KeyExchange.clientSessionKeys clientKp serverKp.publicKey with
    | some clientKeys =>
      match ← KeyExchange.serverSessionKeys serverKp clientKp.publicKey with
      | some serverKeys =>
        -- Verify that client's tx matches server's rx
        let clientTxHex ← Utils.toHex clientKeys.tx
        let serverRxHex ← Utils.toHex serverKeys.rx
        match clientTxHex, serverRxHex with
        | some ct, some sr =>
          Zlog.debug s!"Client TX == Server RX: {ct == sr}"
        | _, _ => pure ()
      | none => Zlog.error "Failed to derive server session keys"
    | none => Zlog.error "Failed to derive client session keys"
  | _, _ => Zlog.error "Key exchange key generation failed"

  -- ============================================================
  -- Streaming Hash
  -- ============================================================
  Zlog.info "=== Streaming Hash ==="

  match ← StreamingHash.State.init with
  | some hashState =>
    let _ ← hashState.updateString "Hello, "
    let _ ← hashState.updateString "streaming "
    let _ ← hashState.updateString "world!"
    match ← hashState.final with
    | some h =>
      match ← Utils.toHex h with
      | some hex => Zlog.debug s!"Streaming hash: {hex}"
      | none => pure ()
    | none => Zlog.error "Failed to finalize streaming hash"
  | none => Zlog.error "Failed to init streaming hash"

  -- ============================================================
  -- Short Hash (SipHash)
  -- ============================================================
  Zlog.info "=== Short Hash (SipHash) ==="

  let shKey ← ShortHash.Key.generate
  match ← ShortHash.hashString "hello" shKey with
  | some h =>
    match ← h.toHex with
    | some hex => Zlog.debug s!"Short hash: {hex}"
    | none => pure ()
    Zlog.debug s!"As UInt64: {h.toUInt64}"
  | none => Zlog.error "Short hash failed"

  -- ============================================================
  -- AEAD (XChaCha20-Poly1305)
  -- ============================================================
  Zlog.info "=== AEAD Encryption ==="

  let aeadKey ← AEAD.Key.generate
  let aeadNonce ← AEAD.Nonce.generate
  let aeadMsg := "Encrypted message".toUTF8
  let aeadAd := "Associated data".toUTF8  -- Authenticated but not encrypted

  match ← AEAD.encrypt aeadMsg aeadAd aeadNonce aeadKey with
  | some ciphertext =>
    Zlog.debug s!"AEAD encrypted: {ciphertext.size} bytes"
    match ← AEAD.decrypt ciphertext aeadAd aeadNonce aeadKey with
    | some decrypted =>
      match String.fromUTF8? decrypted with
      | some s => Zlog.debug s!"AEAD decrypted: {s}"
      | none => Zlog.warn "Invalid UTF-8"
    | none => Zlog.error "AEAD decryption failed"
    -- Test with wrong AD (should fail)
    match ← AEAD.decrypt ciphertext "wrong AD".toUTF8 aeadNonce aeadKey with
    | some _ => Zlog.error "AEAD should have failed with wrong AD!"
    | none => Zlog.debug "AEAD correctly rejected wrong AD"
  | none => Zlog.error "AEAD encryption failed"

  Zlog.info "All examples completed successfully!"

  -- Cleanup zlog
  Zlog.fini
