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

### `buildMinimalPrivateKey` Removed

The `RSAFacade::buildMinimalPrivateKey(\Math_BigInteger $n, \Math_BigInteger $d)` method uses internal phpseclib 2.x methods (`_getPrivatePublicKey`) that don't exist in 3.x. phpseclib 3.x has no equivalent: `PublicKeyLoader::load(['n' => …, 'e' => …, 'd' => …])` returns a **public** key (`d` is dropped), so the exported PEM is `RSA PUBLIC KEY` and `_RSAPrivateKeyPEMFormat` rejects it.

**Change:** `buildMinimalPrivateKey()` is removed. The `RSAJWK` constructor builds a private key only from the full CRT parameter set (`p`, `q`, `dp`, `dq`, `qi`, RFC 7518 §6.3.2) and throws `RSAJWKMissingPrivateKeyParamException` when only `d` is present.

**Impact assessment:**
- **openstackid** — never calls `buildMinimalPrivateKey` directly. All key creation goes through PEM-based factories. **No impact from this change.** openstackid is affected by the compat removal itself, see below.
- **summit-api** — does not depend on JOSE4PHP. **No impact.**
- **Internal caller (RSAJWK constructor)** — the minimal branch was not reachable in practice (the private-key branch is gated by `in_array()` over the header values, and `JWKSet::fromJson()` only builds public keys).

This removes a public method, which is part of this major release.

### Downstream: openstackid relies on the compat layer

openstackid does not require `phpseclib/phpseclib2_compat` itself; it gets it transitively through JOSE4PHP 2.x, and uses the 2.x API directly (`phpseclib\Crypt\RSA`, `phpseclib\Crypt\Random`). Before openstackid moves to this release it must migrate those call sites to `phpseclib3\*` (or require `phpseclib/phpseclib2_compat` itself). The list is in the pull request's deployment note.

## Consequences

**Positive:**
- Removes `phpseclib/phpseclib2_compat` dependency
- All RSA operations use phpseclib 3.x immutable key API (cleaner, no shared mutable state)
- `CustomAsymmetricKey` decorator class can be simplified (direct property access on loaded keys)
- `ByteUtil::randomBytes()` uses `phpseclib3\Crypt\Random::string()` (consistent phpseclib usage)
- Eliminates risk of compat layer being abandoned upstream

**Negative:**
- `RSAFacade::buildMinimalPrivateKey()` is removed; a private RSA JWK needs the CRT parameters
- Consumers using the 2.x API through the transitive compat package (openstackid) must migrate before upgrading
- `Abstract_RSA_Algorithm` and subclasses need rework (mutable RSA object → immutable key pattern)

**Neutral:**
- All existing tests must pass without modification (same cryptographic behavior)
- No changes to the public JOSE API (JWT/JWS/JWE creation and verification)
