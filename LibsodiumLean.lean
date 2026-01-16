/-
  LibsodiumLean - Lean bindings for libsodium cryptographic library

  This library provides a complete wrapper for libsodium, including:
  - Random number generation
  - Cryptographic hashing (BLAKE2b, SHA-256, SHA-512)
  - Streaming/incremental hashing
  - Short-input hashing (SipHash for hash tables)
  - Secret-key encryption (XSalsa20-Poly1305)
  - Public-key encryption (X25519-XSalsa20-Poly1305)
  - AEAD encryption (XChaCha20-Poly1305-IETF)
  - Secret stream encryption (chunked authenticated encryption)
  - Digital signatures (Ed25519)
  - Message authentication (HMAC-SHA512-256)
  - Password hashing (Argon2id)
  - Key derivation
  - Key exchange (X25519 + BLAKE2b)
-/

import LibsodiumLean.FFI
import LibsodiumLean.Init
import LibsodiumLean.Random
import LibsodiumLean.Hash
import LibsodiumLean.StreamingHash
import LibsodiumLean.ShortHash
import LibsodiumLean.SecretBox
import LibsodiumLean.Box
import LibsodiumLean.AEAD
import LibsodiumLean.SecretStream
import LibsodiumLean.Sign
import LibsodiumLean.Auth
import LibsodiumLean.Password
import LibsodiumLean.KDF
import LibsodiumLean.KeyExchange
import LibsodiumLean.Utils
