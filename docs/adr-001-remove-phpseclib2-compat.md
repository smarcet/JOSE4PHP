# ADR-001: Remove phpseclib2_compat Dependency

**Date:** 2026-03-23
**Status:** Proposed
**Deciders:** Sebastian Marcet

## Context

JOSE4PHP migrated from phpseclib 2.x to phpseclib 3.x (commit `8459ceb`), but relied on the `phpseclib/phpseclib2_compat` bridge package to avoid rewriting all call sites. This compat layer maps the phpseclib 2.x API (`phpseclib\Crypt\RSA`, `phpseclib\Crypt\AES`, `phpseclib\Crypt\Random`, `phpseclib\File\X509`, `phpseclib\Math\BigInteger`) to phpseclib 3.x internals.

The compat layer introduces an unnecessary transitive dependency, may not receive long-term maintenance, and prevents the codebase from using phpseclib 3.x features directly (immutable key objects, fluent configuration with `withHash()`/`withPadding()`).

## Decision

Migrate all code from the phpseclib 2.x compat API (`phpseclib\*`) to the native phpseclib 3.x API (`phpseclib3\*`), then remove `phpseclib/phpseclib2_compat` from `composer.json`.

### Key API Changes

| phpseclib 2.x (compat) | phpseclib 3.x (native) |
|------------------------|------------------------|
| `new RSA()` + `loadKey()` + `setHash()` + `sign()` | `PublicKeyLoader::load()` → `withHash()` → `withPadding()` → `sign()` |
| `$rsa->setEncryptionMode()` + `encrypt()` | `$key->withPadding()` → `encrypt()` |
| `RSA::PRIVATE_FORMAT_PKCS1` | `'PKCS1'` string for `toString()` |
| `new AES(AES::MODE_CBC)` | `new AES('cbc')` |
| `phpseclib\Crypt\Random::string($len)` | `phpseclib3\Crypt\Random::string($len)` |
| `new X509()` / `loadX509()` | `new X509()` / `loadX509()` (namespace change only) |

### `buildMinimalPrivateKey` Signature Change

The `RSAFacade::buildMinimalPrivateKey(\Math_BigInteger $n, \Math_BigInteger $d)` method uses internal phpseclib 2.x methods (`_getPrivatePublicKey`) that don't exist in 3.x. phpseclib 3.x's `PublicKeyLoader::load()` requires at minimum `n`, `e`, and `d`.

**Change:** The method signature becomes `buildMinimalPrivateKey(BigInteger $n, BigInteger $e, BigInteger $d)`.

**Impact assessment:**
- **openstackid** — never calls `buildMinimalPrivateKey` directly. All key creation goes through PEM-based factories. **No impact.**
- **summit-api** — does not depend on JOSE4PHP. **No impact.**
- **Internal caller (RSAJWK constructor)** — already has `e` available at the call site (parsed from JWK public params). Only needs to pass the additional argument.

This is technically a signature change on a public method, but has zero practical impact on known consumers.

## Consequences

**Positive:**
- Removes `phpseclib/phpseclib2_compat` dependency
- All RSA operations use phpseclib 3.x immutable key API (cleaner, no shared mutable state)
- `CustomAsymmetricKey` decorator class can be simplified (direct property access on loaded keys)
- `ByteUtil::randomBytes()` uses `phpseclib3\Crypt\Random::string()` (consistent phpseclib usage)
- Eliminates risk of compat layer being abandoned upstream

**Negative:**
- `buildMinimalPrivateKey` gains an additional required parameter (`e`)
- `Abstract_RSA_Algorithm` and subclasses need rework (mutable RSA object → immutable key pattern)

**Neutral:**
- All existing tests must pass without modification (same cryptographic behavior)
- No changes to the public JOSE API (JWT/JWS/JWE creation and verification)
