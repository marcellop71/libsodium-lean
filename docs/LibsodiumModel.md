# LibsodiumModel - Formal Specification Proposal

A proposal for a formal mathematical model of libsodium-lean, inspired by the RedisModel approach.

## Background: The RedisModel Approach

The `redis-lean/RedisModel/AbstractMinimal.lean` demonstrates how to create a formal mathematical specification:

1. **Core Abstraction**: Models Redis as a state monad `RedisM DB α`
2. **Abstract Operations**: A typeclass `AbstractOps` defining `set`, `get`, `del`, `existsKey`
3. **Axiom System**: ~12 axioms capturing operational semantics
4. **Proven Theorems**: Idempotence, commutativity, cancellation, algebraic laws

## What Could LibsodiumModel Formalize?

Libsodium-lean wraps cryptographic primitives. The model could formalize:

---

## 1. Symmetric Encryption Model (SecretBox)

Formalizes the encrypt/decrypt round-trip property.

```lean
namespace LibsodiumModel.SecretBox

-- Opaque types for cryptographic objects
opaque Key : Type
opaque Nonce : Type
opaque Plaintext : Type
opaque Ciphertext : Type

-- Core operations
def encrypt : Key → Nonce → Plaintext → Ciphertext := ...
def decrypt : Key → Nonce → Ciphertext → Option Plaintext := ...

-- Fundamental axiom: decrypt inverts encrypt
axiom encrypt_decrypt_roundtrip : ∀ (k : Key) (n : Nonce) (m : Plaintext),
  decrypt k n (encrypt k n m) = some m

-- Different key fails to decrypt
axiom wrong_key_fails : ∀ (k1 k2 : Key) (n : Nonce) (m : Plaintext),
  k1 ≠ k2 → decrypt k2 n (encrypt k1 n m) = none

-- Different nonce fails to decrypt
axiom wrong_nonce_fails : ∀ (k : Key) (n1 n2 : Nonce) (m : Plaintext),
  n1 ≠ n2 → decrypt k n2 (encrypt k n1 m) = none

-- Ciphertext is at least as long as plaintext + MAC
axiom ciphertext_length : ∀ (k : Key) (n : Nonce) (m : Plaintext),
  length (encrypt k n m) = length m + macLength

-- Theorems
theorem encryption_is_injective : ∀ (k : Key) (n : Nonce) (m1 m2 : Plaintext),
  encrypt k n m1 = encrypt k n m2 → m1 = m2
```

---

## 2. Public-Key Encryption Model (Box)

Formalizes asymmetric encryption properties.

```lean
namespace LibsodiumModel.Box

-- Key types
structure KeyPair where
  publicKey : PublicKey
  secretKey : SecretKey

-- Operations
def encrypt : Plaintext → Nonce → PublicKey → SecretKey → Ciphertext := ...
def decrypt : Ciphertext → Nonce → PublicKey → SecretKey → Option Plaintext := ...

-- Sender encrypts with recipient's public key and own secret key
-- Recipient decrypts with sender's public key and own secret key
axiom box_roundtrip : ∀ (sender recipient : KeyPair) (n : Nonce) (m : Plaintext),
  decrypt (encrypt m n recipient.publicKey sender.secretKey) n
          sender.publicKey recipient.secretKey = some m

-- Commutativity of shared secret derivation (Diffie-Hellman property)
axiom dh_commutativity : ∀ (kp1 kp2 : KeyPair),
  sharedSecret kp1.secretKey kp2.publicKey =
  sharedSecret kp2.secretKey kp1.publicKey

-- Third party cannot decrypt
axiom third_party_fails : ∀ (sender recipient attacker : KeyPair) (n : Nonce) (m : Plaintext),
  attacker.secretKey ≠ recipient.secretKey →
  decrypt (encrypt m n recipient.publicKey sender.secretKey) n
          sender.publicKey attacker.secretKey = none
```

---

## 3. Digital Signatures Model (Sign)

Formalizes Ed25519 signature properties.

```lean
namespace LibsodiumModel.Sign

-- Types
opaque SigningKey : Type
opaque VerifyKey : Type
opaque Message : Type
opaque Signature : Type

-- Operations
def sign : Message → SigningKey → Signature := ...
def verify : Signature → Message → VerifyKey → Bool := ...

-- Fundamental axiom: signatures verify with correct key
axiom sign_verify_correct : ∀ (kp : KeyPair) (m : Message),
  verify (sign m kp.secretKey) m kp.publicKey = true

-- Signatures don't verify with wrong key
axiom wrong_key_verify_fails : ∀ (kp1 kp2 : KeyPair) (m : Message),
  kp1.publicKey ≠ kp2.publicKey →
  verify (sign m kp1.secretKey) m kp2.publicKey = false

-- Signatures don't verify for different messages
axiom different_message_fails : ∀ (kp : KeyPair) (m1 m2 : Message),
  m1 ≠ m2 →
  verify (sign m1 kp.secretKey) m2 kp.publicKey = false

-- Determinism: same message + key = same signature
axiom sign_deterministic : ∀ (k : SigningKey) (m : Message),
  sign m k = sign m k

-- Unforgeability (computational assumption, stated as axiom)
axiom unforgeability : ∀ (kp : KeyPair) (m : Message) (forgedSig : Signature),
  forgedSig ≠ sign m kp.secretKey →
  verify forgedSig m kp.publicKey = false
```

---

## 4. Hash Functions Model

Formalizes cryptographic hash properties.

```lean
namespace LibsodiumModel.Hash

opaque Digest : Type
opaque Input : Type

def hash : Input → Digest := ...

-- Determinism
axiom hash_deterministic : ∀ (m : Input),
  hash m = hash m

-- Different inputs (almost always) different outputs
-- Note: Collision resistance is computational, stated weakly
axiom collision_resistance_weak : ∀ (m1 m2 : Input),
  m1 ≠ m2 → hash m1 ≠ hash m2  -- Idealized; real hash has rare collisions

-- Fixed output length
axiom hash_length : ∀ (m : Input),
  length (hash m) = digestLength

-- Pre-image resistance (one-way property)
-- Cannot formalize computationally, but can state behavior
axiom preimage_opaque : ∀ (d : Digest),
  -- No efficient way to find m such that hash m = d
  True  -- Placeholder; real property is computational
```

---

## 5. Key Derivation Model (KDF)

Formalizes key derivation function properties.

```lean
namespace LibsodiumModel.KDF

-- Derive subkey from master key
def deriveKey : MasterKey → Context → SubkeyId → SubKey := ...

-- Determinism
axiom kdf_deterministic : ∀ (mk : MasterKey) (ctx : Context) (id : SubkeyId),
  deriveKey mk ctx id = deriveKey mk ctx id

-- Different IDs yield different keys
axiom kdf_different_ids : ∀ (mk : MasterKey) (ctx : Context) (id1 id2 : SubkeyId),
  id1 ≠ id2 → deriveKey mk ctx id1 ≠ deriveKey mk ctx id2

-- Different contexts yield different keys
axiom kdf_different_contexts : ∀ (mk : MasterKey) (ctx1 ctx2 : Context) (id : SubkeyId),
  ctx1 ≠ ctx2 → deriveKey mk ctx1 id ≠ deriveKey mk ctx2 id

-- Independence: knowing one subkey reveals nothing about others
axiom kdf_independence : ∀ (mk : MasterKey) (ctx : Context) (id1 id2 : SubkeyId),
  id1 ≠ id2 →
  independent (deriveKey mk ctx id1) (deriveKey mk ctx id2)
```

---

## Comparison with RedisModel

| Aspect | RedisModel | LibsodiumModel |
|--------|------------|----------------|
| Core abstraction | Key-value store | Cryptographic primitives |
| State type | DB (opaque) | Keys, Nonces (opaque) |
| Operations | GET, SET, DEL | encrypt, decrypt, sign, verify |
| Key invariants | set-get consistency | round-trip, unforgeability |
| Composition | monadic DB ops | key derivation chains |

---

## Recommended Implementation Order

1. **SecretBox** - Simplest, symmetric encryption round-trip
2. **Sign** - Clear sign/verify duality
3. **Box** - Builds on symmetric model + key exchange
4. **Hash** - Standalone, simpler properties
5. **KDF** - Depends on key concepts from above

## Why Model Cryptography Formally?

1. **API Correctness**: Ensure bindings preserve cryptographic guarantees
2. **Usage Patterns**: Formalize correct usage (nonce uniqueness, etc.)
3. **Composition**: Prove higher-level protocols built on primitives are sound
4. **Documentation**: Precise specification of security properties
