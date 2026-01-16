# libsodium-lean

Lean 4 bindings for [libsodium](https://doc.libsodium.org/), a modern, portable, easy-to-use crypto library.

> ⚠️ **Warning**: this is work in progress, it is still incomplete and it ~~may~~ will contain errors

## AI Assistance Disclosure

Parts of this repository were created with assistance from AI-powered coding tools, specifically Claude by Anthropic. Not all generated code may have been reviewed. Generated code may have been adapted by the author. Design choices, architectural decisions, and final validation were performed independently by the author.

## Features

- **Random Number Generation** - Cryptographically secure random bytes
- **Hashing** - BLAKE2b, SHA-256, SHA-512
- **Streaming Hash** - Incremental BLAKE2b for large data
- **Short-Input Hash** - SipHash-2-4 for hash tables
- **Secret-key Encryption** - XSalsa20-Poly1305 (secretbox)
- **AEAD Encryption** - XChaCha20-Poly1305-IETF with associated data
- **Secret Stream** - Chunked authenticated encryption for files/streams
- **Public-key Encryption** - X25519-XSalsa20-Poly1305 (box)
- **Sealed Boxes** - Anonymous public-key encryption
- **Digital Signatures** - Ed25519
- **Message Authentication** - HMAC-SHA512-256
- **Password Hashing** - Argon2id
- **Key Derivation** - Derive multiple keys from a master key
- **Key Exchange** - X25519 + BLAKE2b for secure channels

## Requirements

- Lean 4
- libsodium development library
- zlog logging library (for examples)

### Installing libsodium

**Ubuntu/Debian:**
```bash
sudo apt install libsodium-dev
```

**macOS:**
```bash
brew install libsodium
```

**From source:**
```bash
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar xzf LATEST.tar.gz
cd libsodium-stable
./configure
make && make check
sudo make install
```

### Installing zlog (for examples)

**Ubuntu/Debian:**
```bash
sudo apt install libzlog-dev
```

**From source:**
```bash
git clone https://github.com/HardySimpson/zlog.git
cd zlog
make && sudo make install
```

## Installation

Add to your `lakefile.lean`:

```lean
require libsodiumLean from git
  "https://github.com/yourusername/libsodium-lean.git" @ "main"
```

## Usage

### Initialization

Always initialize libsodium before using any functions:

```lean
import LibsodiumLean

def main : IO Unit := do
  let ok ← Sodium.init
  unless ok do
    IO.println "Failed to initialize libsodium"
    return
  -- Use libsodium functions...
```

### Random Number Generation

```lean
-- Random 32-bit integer
let n ← Sodium.Random.uint32

-- Random integer in [0, 100)
let r ← Sodium.Random.uniform 100

-- Random bytes
let bytes ← Sodium.Random.bytes 32
```

### Hashing

```lean
let data := "Hello, World!".toUTF8

-- BLAKE2b (default, recommended)
let hash ← Sodium.Hash.blake2b data

-- SHA-256
let hash256 ← Sodium.Hash.sha256 data

-- SHA-512
let hash512 ← Sodium.Hash.sha512 data
```

### Secret-key Encryption

For encrypting data when both parties share a secret key:

```lean
-- Generate key and nonce
let key ← Sodium.SecretBox.Key.generate
let nonce ← Sodium.SecretBox.Nonce.generate

-- Encrypt
let plaintext := "Secret message".toUTF8
let ciphertext ← Sodium.SecretBox.encrypt plaintext nonce key

-- Decrypt
let decrypted ← Sodium.SecretBox.decrypt ciphertext.get! nonce key
```

### Public-key Encryption

For encrypting data between two parties:

```lean
-- Generate key pairs
let alice ← Sodium.Box.KeyPair.generate
let bob ← Sodium.Box.KeyPair.generate

-- Alice encrypts to Bob
let nonce ← Sodium.Box.Nonce.generate
let ciphertext ← Sodium.Box.encrypt message nonce bob.get!.publicKey alice.get!.secretKey

-- Bob decrypts from Alice
let plaintext ← Sodium.Box.decrypt ciphertext.get! nonce alice.get!.publicKey bob.get!.secretKey
```

### Sealed Boxes (Anonymous Encryption)

When the sender doesn't need to authenticate:

```lean
let recipient ← Sodium.Box.KeyPair.generate

-- Anonymous encrypt
let sealed ← Sodium.Box.Sealed.encrypt message recipient.get!.publicKey

-- Recipient decrypts
let opened ← Sodium.Box.Sealed.decrypt sealed.get! recipient.get!.publicKey recipient.get!.secretKey
```

### Digital Signatures

```lean
-- Generate signing key pair
let keyPair ← Sodium.Sign.KeyPair.generate

-- Sign a message
let signature ← Sodium.Sign.sign message keyPair.get!.secretKey

-- Verify signature
let valid ← Sodium.Sign.verify signature.get! message keyPair.get!.publicKey
```

### Message Authentication

```lean
-- Generate key
let key ← Sodium.Auth.Key.generate

-- Authenticate message
let tag ← Sodium.Auth.authenticate message key

-- Verify
let valid ← Sodium.Auth.verify tag.get! message key
```

### Password Hashing

```lean
-- Hash password for storage
let hash ← Sodium.Password.hashStringForStorage "my password" .interactive

-- Verify password
let valid ← Sodium.Password.verifyStringStorage hash.get! "my password"

-- Derive key from password
let salt ← Sodium.Password.Salt.generate
let key ← Sodium.Password.deriveKeyFromString "my password" salt 32 .interactive
```

### Key Derivation

Derive multiple keys from a master key:

```lean
let masterKey ← Sodium.KDF.MasterKey.generate
let context := Sodium.KDF.Context.make "myapp"

-- Derive subkeys
let encKey ← Sodium.KDF.deriveSubkey masterKey 0 context 32
let authKey ← Sodium.KDF.deriveSubkey masterKey 1 context 32
```

### Key Exchange

Establish secure session keys between client and server:

```lean
-- Generate key pairs for client and server
let clientKp ← Sodium.KeyExchange.KeyPair.generate
let serverKp ← Sodium.KeyExchange.KeyPair.generate

-- Client derives session keys
let clientKeys ← Sodium.KeyExchange.clientSessionKeys clientKp.get! serverKp.get!.publicKey

-- Server derives session keys
let serverKeys ← Sodium.KeyExchange.serverSessionKeys serverKp.get! clientKp.get!.publicKey

-- Client's tx key == Server's rx key (and vice versa)
-- Use clientKeys.get!.tx for sending, clientKeys.get!.rx for receiving
```

### AEAD Encryption

Authenticated encryption with associated data (authenticated but not encrypted):

```lean
let key ← Sodium.AEAD.Key.generate
let nonce ← Sodium.AEAD.Nonce.generate

let message := "Secret message".toUTF8
let associatedData := "metadata".toUTF8  -- Authenticated but not encrypted

-- Encrypt
let ciphertext ← Sodium.AEAD.encrypt message associatedData nonce key

-- Decrypt (fails if AD doesn't match)
let decrypted ← Sodium.AEAD.decrypt ciphertext.get! associatedData nonce key

-- Auto-nonce variant (nonce prepended to ciphertext)
let encrypted ← Sodium.AEAD.encryptWithNonce message associatedData key
let decrypted ← Sodium.AEAD.decryptWithNonce encrypted.get! associatedData key
```

### Secret Stream

Chunked authenticated encryption for files and streams:

```lean
let key ← Sodium.SecretStream.Key.generate

-- Encryption (push)
match ← Sodium.SecretStream.PushState.init key with
| some (pushState, header) =>
  -- Encrypt chunks
  let chunk1 ← pushState.push "Hello ".toUTF8 .message
  let chunk2 ← pushState.push "World".toUTF8 .final  -- Mark final chunk
| none => -- handle error

-- Decryption (pull)
match ← Sodium.SecretStream.PullState.init header key with
| some pullState =>
  -- Decrypt chunks
  match ← pullState.pull ciphertext1 with
  | some (plaintext, tag) =>
    -- tag is .message, .push, .rekey, or .final
  | none => -- decryption failed
| none => -- handle error
```

### Streaming Hash

Hash data incrementally (for large files):

```lean
-- Initialize streaming hash
match ← Sodium.StreamingHash.State.init with
| some state =>
  -- Update with chunks
  let _ ← state.updateString "Hello, "
  let _ ← state.updateString "World!"
  -- Finalize
  let hash ← state.final
| none => -- handle error

-- Or hash multiple chunks at once
let hash ← Sodium.StreamingHash.hashChunks #[chunk1, chunk2, chunk3]
```

### Short-Input Hash (SipHash)

Keyed hash for hash tables (prevents HashDoS):

```lean
let key ← Sodium.ShortHash.Key.generate

-- Hash to 8 bytes
let hash ← Sodium.ShortHash.hashString "key" key

-- Get as UInt64 for use in hash tables
let hashValue ← Sodium.ShortHash.hashStringToUInt64 "key" key
-- hashValue.get! can be used as a hash table key
```

## Monadic Interfaces

For convenient chaining of operations, monadic interfaces are available:

```lean
-- SecretBox monad
Sodium.SecretBox.SecretBoxM.runWith (do
  let encrypted ← SecretBoxM.encryptAuto message
  let decrypted ← SecretBoxM.decryptAuto encrypted.get!
  return decrypted
) key

-- Sign monad
Sodium.Sign.SignerM.runWith (do
  let sig1 ← SignerM.sign msg1
  let sig2 ← SignerM.sign msg2
  return (sig1, sig2)
) secretKey
```

## Utilities

```lean
-- Convert to/from hex
let hex ← Sodium.Utils.toHex bytes
let bytes ← Sodium.Utils.fromHex hex.get!

-- Constant-time comparison (for secrets)
let equal ← Sodium.Utils.secureCompare a b

-- Zero memory
let zeroed ← Sodium.Utils.memzero sensitiveData
```

## Building

```bash
lake build
```

## Running Examples

The examples use zlog for structured logging. Run from the project root directory:

```bash
lake exe examples
```

Example output:
```
INFO [sodium] libsodium version: 1.0.18
INFO [sodium] === Random Number Generation ===
INFO [sodium] === Hashing ===
INFO [sodium] === Secret-key Encryption ===
INFO [sodium] === Public-key Encryption ===
INFO [sodium] === Sealed Box (Anonymous Encryption) ===
INFO [sodium] === Digital Signatures ===
INFO [sodium] === Message Authentication ===
INFO [sodium] === Password Hashing ===
INFO [sodium] === Key Derivation ===
INFO [sodium] === Secret Stream ===
INFO [sodium] === Key Exchange ===
INFO [sodium] === Streaming Hash ===
INFO [sodium] === Short Hash (SipHash) ===
INFO [sodium] === AEAD Encryption ===
INFO [sodium] All examples completed successfully!
```

## Security Notes

1. **Always initialize** libsodium with `Sodium.init` before using any functions
2. **Use appropriate security levels** for password hashing based on your use case
3. **Never reuse nonces** with the same key
4. **Use constant-time comparison** (`secureCompare`) when comparing secrets
5. **Zero sensitive data** when done using `memzero`
