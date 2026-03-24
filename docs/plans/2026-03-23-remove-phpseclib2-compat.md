# Remove phpseclib2_compat Dependency Implementation Plan

Created: 2026-03-23
Status: VERIFIED
Approved: Yes
Iterations: 0
Worktree: No
Type: Feature

## Summary

**Goal:** Remove the `phpseclib/phpseclib2_compat` dependency by migrating all `phpseclib\*` (2.x compat) imports to native `phpseclib3\*` APIs.
**Architecture:** phpseclib 3.x uses immutable key objects with fluent configuration (`withHash()`, `withPadding()`) instead of the 2.x mutable RSA object pattern. The migration replaces the mutable `$rsa_impl` pattern in algorithm classes with per-operation key loading and configuration.
**Tech Stack:** PHP 8.3, phpseclib 3.0.43

## Scope

### In Scope

- Migrate all 14 files that import from `phpseclib\*` namespace to `phpseclib3\*`
- Rewrite `Abstract_RSA_Algorithm` and subclasses to use immutable key API
- Rewrite `_AbstractRSAKeyPEMFormat` hierarchy to drop the 2.x RSA object
- Rewrite `RSAFacade` key-building methods for phpseclib 3.x
- Simplify `CustomAsymmetricKey` decorator
- Replace `phpseclib\Crypt\Random` with `phpseclib3\Crypt\Random`
- Replace `phpseclib\Crypt\AES` with `phpseclib3\Crypt\AES`
- Replace `phpseclib\File\X509` with `phpseclib3\File\X509`
- Remove `phpseclib/phpseclib2_compat` from `composer.json`
- ADR documenting the decision (already written at `docs/adr-001-remove-phpseclib2-compat.md`)

### Out of Scope

- Adding new algorithms or features
- Changing the public JOSE API (JWT/JWS/JWE factory interfaces)
- Updating openstackid's composer.lock (separate repo)

## Context for Implementer

> Write for an implementer who has never seen the codebase.

- **phpseclib 3.x key pattern:** Keys are immutable objects. Load with `PublicKeyLoader::load($pem, $password)`, then configure with `->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1)`. Call `sign()`/`verify()`/`encrypt()`/`decrypt()` on the configured key. Each `with*()` returns a new object.
- **phpseclib 3.x key generation:** `RSA::createKey(2048)` returns a private key. `$private->getPublicKey()` returns the public key. `$key->toString('PKCS1')` exports to PEM.
- **phpseclib 3.x key from components:** `PublicKeyLoader::load(['n' => $n, 'e' => $e, 'd' => $d, ...])` constructs keys from BigInteger components.
- **Current mutable pattern (to remove):** `Abstract_RSA_Algorithm` creates `new RSA()` in constructor, then each `sign()`/`verify()` call mutates the same instance via `loadKey()`, `setHash()`, `setSignatureMode()`. This must become stateless.
- **Conventions:** Namespaces are lowercase matching directory structure. Classes are `final`. Registries are singletons. Factories use `static public function build($spec)`.
- **Key files:**
  - `src/security/rsa/RSAFacade.php` — singleton that builds RSA keys from PEM or components
  - `src/security/rsa/_AbstractRSAKeyPEMFormat.php` — base class for PEM key wrappers
  - `src/security/rsa/CustomAsymmetricKey.php` — decorator to access protected key properties
  - `src/jwa/cryptographic_algorithms/Abstract_RSA_Algorithm.php` — base for all RSA algorithms
  - `src/jwa/cryptographic_algorithms/digital_signatures/rsa/RSA_Algorithm.php` — sign/verify implementation
  - `src/jwa/cryptographic_algorithms/key_management/rsa/RSA_KeyManagementAlgorithm.php` — encrypt/decrypt implementation
- **Gotchas:**
  - `RSAFacade::buildPrivateKey()` uses internal 2.x method `_convertPrivateKey()` — must replace with `PublicKeyLoader::load()` from components
  - `RSAFacade::buildMinimalPrivateKey()` uses internal 2.x method `_getPrivatePublicKey()` — requires signature change to add `e` parameter
  - `_AbstractRSAKeyPEMFormat` does dual initialization: old RSA for validation + new `PublicKeyLoader` for actual use. Remove the old RSA path entirely.
  - `_RSAPublicKeyPEMFormat::getEncoded()` and `getBitLength()` use old RSA methods (`getPublicKey()`, `getSize()`) — replace with phpseclib3 key methods
  - `_RSAPrivateKeyPEMFormat::getEncoded()` uses old `getPrivateKey()` — replace with phpseclib3 `toString('PKCS1')`
  - `AES_CBC_HMAC_SHA2_Algorithm` uses `new AES(AES::MODE_CBC)` — in 3.x this is `new AES('cbc')`

## Assumptions

- phpseclib 3.x `PublicKeyLoader::load()` with array of BigInteger components (n, e, d, p, q) produces valid private keys — supported by phpseclib 3.x docs. Tasks 3, 4 depend on this.
- phpseclib 3.x `RSA::SIGNATURE_PSS`, `RSA::SIGNATURE_PKCS1`, `RSA::ENCRYPTION_OAEP`, `RSA::ENCRYPTION_PKCS1` constants exist on `phpseclib3\Crypt\RSA` — supported by phpseclib 3.x source. Tasks 4, 5 depend on this.
- `phpseclib3\File\X509` has the same `loadX509()` and `getPublicKey()` API as the compat layer — supported by context7 docs. Task 2 depends on this.
- `phpseclib3\Crypt\AES` constructor accepts mode as string `'cbc'` — supported by phpseclib 3.x docs. Task 6 depends on this.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| phpseclib 3.x key from components (n,e,d without CRT) fails | Low | High | Test with JOSE4PHP's existing JWK test that constructs keys from components |
| Signature output differs between 2.x compat and 3.x native for PSS | Low | High | PSS is non-deterministic by design; verify with round-trip sign+verify tests |
| AES CBC output changes | Very Low | High | Existing JWE encryption/decryption tests cover this |
| `_RSAPrivateKeyPEMFormat` validation changes behavior (currently uses old `loadKey` + new `PublicKeyLoader`) | Medium | Medium | Keep same validation: attempt `PublicKeyLoader::load()`, throw `RSABadPEMFormat` on failure |

## Goal Verification

### Truths

1. `composer show phpseclib/phpseclib2_compat` returns "not installed"
2. `grep -r "use phpseclib\\\\" src/` returns zero matches (no 2.x compat imports remain)
3. `vendor/bin/phpunit` passes all existing tests with 0 failures
4. JWS sign+verify round-trip works for RS256, RS384, RS512, PS256, PS384, PS512
5. JWE encrypt+decrypt round-trip works for RSA-OAEP, RSA-OAEP-256, RSA1_5
6. Password-protected private key loading still works

### Artifacts

- `composer.json` — `phpseclib/phpseclib2_compat` removed from `require`
- All 14 modified source files under `src/`
- `docs/adr-001-remove-phpseclib2-compat.md` — ADR documenting the decision

## Progress Tracking

- [x] Task 1: Migrate ByteUtil (Random)
- [x] Task 2: Migrate X509Certificate
- [x] Task 3: Migrate RSA security layer (key wrappers, facade, CustomAsymmetricKey)
- [x] Task 4: Migrate RSA digital signature algorithms
- [x] Task 5: Migrate RSA key management algorithms
- [x] Task 6: Migrate AES content encryption
- [x] Task 7: Remove phpseclib2_compat dependency and run full test suite

**Total Tasks:** 7 | **Completed:** 7 | **Remaining:** 0

## Implementation Tasks

### Task 1: Migrate ByteUtil (Random)

**Objective:** Replace `phpseclib\Crypt\Random::string()` with `phpseclib3\Crypt\Random::string()`.
**Dependencies:** None

**Files:**

- Modify: `src/utils/ByteUtil.php`

**Key Decisions / Notes:**

- Change namespace import from `phpseclib\Crypt\Random` to `phpseclib3\Crypt\Random`
- `Random::string()` API is identical in phpseclib 3.x
- Keeps all crypto operations going through phpseclib for consistency

**Definition of Done:**

- [ ] `ByteUtil::randomBytes()` uses `phpseclib3\Crypt\Random::string()`
- [ ] No `phpseclib\` (2.x compat) import in ByteUtil.php
- [ ] `vendor/bin/phpunit` passes

**Verify:**

- `vendor/bin/phpunit`

---

### Task 2: Migrate X509Certificate

**Objective:** Replace `phpseclib\File\X509` with `phpseclib3\File\X509`.
**Dependencies:** None

**Files:**

- Modify: `src/security/x509/_X509Certificate.php`

**Key Decisions / Notes:**

- The phpseclib 3.x `X509` class has the same `loadX509()` and `getPublicKey()` API
- Only the namespace changes: `phpseclib\File\X509` → `phpseclib3\File\X509`

**Definition of Done:**

- [ ] Import changed to `phpseclib3\File\X509`
- [ ] No `phpseclib\` imports remain
- [ ] `vendor/bin/phpunit` passes

**Verify:**

- `vendor/bin/phpunit`

---

### Task 3: Migrate RSA Security Layer

**Objective:** Rewrite the RSA key wrapper hierarchy and RSAFacade to use phpseclib 3.x native API exclusively.
**Dependencies:** None

**Files:**

- Modify: `src/security/rsa/_AbstractRSAKeyPEMFormat.php`
- Modify: `src/security/rsa/_RSAPublicKeyPEMFormat.php`
- Modify: `src/security/rsa/_RSAPrivateKeyPEMFormat.php`
- Modify: `src/security/rsa/CustomAsymmetricKey.php`
- Modify: `src/security/rsa/RSAFacade.php`
- Modify: `src/jwk/impl/RSAJWK.php` (update `buildMinimalPrivateKey` call to pass `e`)

**Key Decisions / Notes:**

**`_AbstractRSAKeyPEMFormat`:**
- Remove `$rsa_imp` (old `phpseclib\Crypt\RSA`) entirely
- Constructor: use `PublicKeyLoader::load($pem, $password)` directly. On failure, throw `RSABadPEMFormat`.
- Store the loaded phpseclib3 key object as `$this->key` (already partially done via `CustomAsymmetricKey`)
- Remove the `CustomAsymmetricKey` wrapper if modulus/exponent can be accessed directly from the loaded key

**`CustomAsymmetricKey`:**
- Currently extends `phpseclib3\Crypt\RSA` and wraps an `AsymmetricKey` to expose `modulus`, `exponent`, `publicExponent` via getters
- Has `use phpseclib\Crypt\RSA as RSA_OLD` import used in `toString()` default parameter `$type = RSA_OLD::PRIVATE_FORMAT_PKCS8`
- Remove `RSA_OLD` import entirely. Change `toString()` default to `$type = 'PKCS8'` (phpseclib 3.x string format)
- Use phpseclib3 key's internal properties or `toString('raw')` to extract components

**`_RSAPublicKeyPEMFormat`:**
- `getEncoded()` currently uses `$this->rsa_imp->getPublicKey(RSA::PUBLIC_FORMAT_PKCS8)` → replace with `$this->key->toString('PKCS8')` (where `$this->key` is the phpseclib3 loaded key)
- `getBitLength()` currently uses `$this->rsa_imp->getSize()` → use the loaded key's bit length

**`_RSAPrivateKeyPEMFormat`:**
- `getEncoded()` currently uses `$this->rsa_imp->getPrivateKey(RSA::PRIVATE_FORMAT_PKCS1)` → replace with `$this->key->toString('PKCS1')` (note: `$this->key` wraps the private key, need to unwrap or store the raw phpseclib3 key)
- Change `phpseclib\Math\BigInteger` import to `phpseclib3\Math\BigInteger`

**`RSAFacade`:**
- `buildKeyPair()`: `RSA::createKey($bits)` → get private PEM with `toString('PKCS1')`, get public PEM with `getPublicKey()->toString('PKCS1')`
- `buildPrivateKey(n, e, d, p, q, dp, dq, qi)`: use `PublicKeyLoader::load(['n'=>$n, 'e'=>$e, 'd'=>$d, 'p'=>$p, 'q'=>$q])` → extract PEM
- `buildMinimalPrivateKey(n, d)`: change signature to `(BigInteger $n, BigInteger $e, BigInteger $d)`, use `PublicKeyLoader::load(['n'=>$n, 'e'=>$e, 'd'=>$d])`
- Remove `$rsa_imp` property and old `RSA` import

**`RSAJWK`:**
- Line 88-91: pass `$this[RSAKeysParameters::Exponent]->toBigInt()` as second arg to `buildMinimalPrivateKey`

**Definition of Done:**

- [ ] No `phpseclib\` (2.x compat) imports in any `src/security/rsa/` file or `src/jwk/impl/RSAJWK.php`
- [ ] `CustomAsymmetricKey.php` has no `use phpseclib\Crypt\RSA as RSA_OLD` import; `toString()` uses `'PKCS8'` string default
- [ ] All `phpseclib\Math\BigInteger` imports changed to `phpseclib3\Math\BigInteger`
- [ ] `RSAFacade::buildMinimalPrivateKey` accepts (n, e, d)
- [ ] Password-protected private key loading works (PEM with password passed to `PublicKeyLoader::load()`)
- [ ] Key building from BigInteger components works
- [ ] `getModulus()`, `getPublicExponent()`, `getPrivateExponent()` return correct values
- [ ] `getEncoded()` returns valid PEM for both public and private keys
- [ ] `vendor/bin/phpunit` passes all JWK and JWS/JWE tests

**Verify:**

- `vendor/bin/phpunit`

---

### Task 4: Migrate RSA Digital Signature Algorithms

**Objective:** Rewrite `Abstract_RSA_Algorithm` and `RSA_Algorithm` to use phpseclib 3.x immutable key API for signing and verification.
**Dependencies:** Task 3 (key wrappers must be migrated first so `getEncoded()` returns correct PEM)

**Files:**

- Modify: `src/jwa/cryptographic_algorithms/Abstract_RSA_Algorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/digital_signatures/rsa/RSA_Algorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/digital_signatures/rsa/PKCS1/RSASSA_PKCS1_v1_5_Algorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/digital_signatures/rsa/PSS/RSASSA_PSS_Algorithm.php`

**Key Decisions / Notes:**

**`Abstract_RSA_Algorithm`:**
- Remove `$rsa_impl` property and constructor that creates `new RSA()`
- The class becomes a simple base with `getKeyType()` and `getMinKeyLen()` — no RSA object needed

**`RSA_Algorithm::sign()`:**
- Currently: `loadKey($key->getEncoded())` → `setHash()` → `setSignatureMode()` → `sign()`
- New: `PublicKeyLoader::load($key->getEncoded(), $key->getPassword())` → `withHash($this->getHashingAlgorithm())` → `withPadding($this->getPaddingMode())` → `sign($message)`

**`RSA_Algorithm::verify()`:**
- Currently: `loadKey($key->getEncoded())` → `setHash()` → `setSignatureMode()` → `verify()`
- New: `PublicKeyLoader::load($key->getEncoded())` → `withHash(...)` → `withPadding(...)` → `verify($message, $signature)`

**`RSASSA_PKCS1_v1_5_Algorithm::getPaddingMode()`:**
- Change `RSA::SIGNATURE_PKCS1` from `phpseclib\Crypt\RSA` to `phpseclib3\Crypt\RSA`

**`RSASSA_PSS_Algorithm::getPaddingMode()`:**
- Change `RSA::SIGNATURE_PSS` from `phpseclib\Crypt\RSA` to `phpseclib3\Crypt\RSA`

**Definition of Done:**

- [ ] No `phpseclib\` imports in any digital signature algorithm file
- [ ] `Abstract_RSA_Algorithm` no longer holds a mutable RSA instance
- [ ] JWS sign + verify round-trips pass for RS256, RS384, RS512, PS256, PS384, PS512
- [ ] `vendor/bin/phpunit` passes

**Verify:**

- `vendor/bin/phpunit --filter JsonWebSignatureTest`

---

### Task 5: Migrate RSA Key Management Algorithms

**Objective:** Rewrite `RSA_KeyManagementAlgorithm` to use phpseclib 3.x immutable key API for CEK encryption/decryption.
**Dependencies:** Task 3, Task 4 (Abstract_RSA_Algorithm must be migrated first)

**Files:**

- Modify: `src/jwa/cryptographic_algorithms/key_management/rsa/RSA_KeyManagementAlgorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/key_management/rsa/PKCS1/RSA1_5_KeyManagementAlgorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/key_management/rsa/OAEP/RSA_OAEP_KeyManagementAlgorithm.php`
- Modify: `src/jwa/cryptographic_algorithms/key_management/rsa/OAEP/RSA_OAEP_256_KeyManagementAlgorithm.php`

**Key Decisions / Notes:**

**`RSA_KeyManagementAlgorithm`:**
- Constructor currently calls `parent::__construct()` then configures `$rsa_impl` with encryption mode, hash, MGF hash
- New: constructor just calls `parent::__construct()` (which is now empty). Configuration happens per-operation.

**`encrypt()`:**
- New: `PublicKeyLoader::load($key->getEncoded())` → `withHash($this->getHashingAlgorithm())` → `withMGFHash($this->getMGFHash())` → `withPadding($this->getEncryptionMode())` → `encrypt($message)`

**`decrypt()`:**
- New: `PublicKeyLoader::load($key->getEncoded())` → `withHash(...)` → `withMGFHash(...)` → `withPadding(...)` → `decrypt($enc_message)`

**Subclass padding constants:**
- `RSA::ENCRYPTION_OAEP` and `RSA::ENCRYPTION_PKCS1` from `phpseclib3\Crypt\RSA`

**Definition of Done:**

- [ ] No `phpseclib\` imports in any key management algorithm file
- [ ] JWE encrypt + decrypt round-trips pass for RSA-OAEP, RSA-OAEP-256, RSA1_5
- [ ] `vendor/bin/phpunit` passes

**Verify:**

- `vendor/bin/phpunit --filter JsonWebEncryptionTest`

---

### Task 6: Migrate AES Content Encryption

**Objective:** Replace `phpseclib\Crypt\AES` with `phpseclib3\Crypt\AES`.
**Dependencies:** None

**Files:**

- Modify: `src/jwa/cryptographic_algorithms/content_encryption/AES_CBC_HS/AES_CBC_HMAC_SHA2_Algorithm.php`

**Key Decisions / Notes:**

- phpseclib 3.x AES constructor: `new AES('cbc')` instead of `new AES(AES::MODE_CBC)`
- `setKey()`, `setIV()`, `encrypt()`, `decrypt()` methods remain the same
- Change import from `phpseclib\Crypt\AES` to `phpseclib3\Crypt\AES`

**Definition of Done:**

- [ ] Import changed to `phpseclib3\Crypt\AES`
- [ ] Constructor uses `new AES('cbc')`
- [ ] JWE encrypt/decrypt tests pass
- [ ] `vendor/bin/phpunit` passes

**Verify:**

- `vendor/bin/phpunit --filter JsonWebEncryptionTest`

---

### Task 7: Remove phpseclib2_compat Dependency

**Objective:** Remove the compat package from composer.json and verify the full test suite passes.
**Dependencies:** Tasks 1-6 (all migrations must be complete)

**Files:**

- Modify: `composer.json`

**Key Decisions / Notes:**

- Remove `"phpseclib/phpseclib2_compat": "1.0.6"` from the `require` section
- Run `composer update` to regenerate lock file
- Run full test suite to verify nothing breaks

**Definition of Done:**

- [ ] `phpseclib/phpseclib2_compat` removed from `composer.json`
- [ ] `composer install` succeeds without errors
- [ ] `grep -r "use phpseclib\\\\" src/` returns zero matches
- [ ] `vendor/bin/phpunit` passes all tests with 0 failures
- [ ] `composer show phpseclib/phpseclib2_compat` reports not installed

**Verify:**

- `composer install && vendor/bin/phpunit`

## Open Questions

None — all questions resolved during planning.
