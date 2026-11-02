# JOSE4PHP Security Audit — Findings Report

Created: 2026-03-24
Status: VERIFIED
Approved: Yes
Iterations: 0
Worktree: No
Type: Feature

## Summary

**Goal:** Produce a security findings report covering timing attacks, padding oracle resistance, key material hygiene, and general crypto safety across JOSE4PHP and its phpseclib 3.x integration layer.

**Architecture:** This is a findings-only report — no code changes. Each finding has a severity, affected file(s), and recommended remediation.

**Scope:** All cryptographic implementation files in `src/`, including how phpseclib 3.x is configured and called.

## Scope

### In Scope

- Timing side-channel analysis (tag comparison, HMAC verification)
- RSA padding oracle resistance (PKCS1v1.5, OAEP error handling)
- Key material hygiene (PEM in memory, secrets in exceptions, zeroing)
- IV/nonce/CEK generation (CSPRNG usage)
- phpseclib 3.x configuration (padding modes, hash algorithms, secure defaults)
- Error message information leakage

### Out of Scope

- EC (ECDSA/ECDH) algorithms — not implemented in this library
- AES Key Wrap algorithms — declared but not implemented
- Network/transport layer security
- PHP runtime configuration (memory_limit, opcache, etc.)

---

## Findings

### Finding 1: Non-Constant-Time Authentication Tag Comparison (CRITICAL)

**Severity:** CRITICAL
**CWE:** CWE-208 (Observable Timing Discrepancy)
**File:** `src/jwa/cryptographic_algorithms/content_encryption/AES_CBC_HS/AES_CBC_HMAC_SHA2_Algorithm.php:109`

**Description:**
The `checkAuthenticationTag()` method uses PHP's `===` operator to compare the computed authentication tag with the provided tag:

```php
protected function checkAuthenticationTag($cypher_text, $key, $iv, $aad, $tag)
{
    return $tag === $this->calculateAuthenticationTag($cypher_text, $key, $iv, $aad);
}
```

The `===` operator performs byte-by-byte comparison and returns `false` as soon as a mismatch is found. This creates a timing side channel: an attacker can measure response times to determine how many leading bytes of their forged tag match the correct tag, enabling iterative forgery of valid authentication tags.

This affects all three AES-CBC-HMAC-SHA2 content encryption algorithms:
- A128CBC-HS256
- A192CBC-HS384
- A256CBC-HS512

**Impact:** An attacker who can observe decryption timing can forge authentication tags, breaking the authenticated encryption guarantee of JWE. This can enable plaintext recovery attacks.

**Recommendation:** Replace `===` with `hash_equals()`:

```php
protected function checkAuthenticationTag($cypher_text, $key, $iv, $aad, $tag)
{
    return hash_equals($this->calculateAuthenticationTag($cypher_text, $key, $iv, $aad), $tag);
}
```

`hash_equals()` is available since PHP 5.6.0 and performs constant-time string comparison. Note: the known-good value (computed tag) must be the first argument.

---

### Finding 2: Non-Constant-Time HMAC Signature Verification (CRITICAL)

**Severity:** CRITICAL
**CWE:** CWE-208 (Observable Timing Discrepancy)
**File:** `src/jwa/cryptographic_algorithms/macs/HSMAC_Algorithm.php:53`

**Description:**
The `verify()` method for HMAC-based JWS signatures uses `===` for digest comparison:

```php
public function verify(Key $key, $message, $digest){
    if(!($key instanceof SharedKey)) throw new InvalidKeyTypeAlgorithmException;
    return $digest === $this->digest($key, $message);
}
```

Same timing side channel as Finding 1. An attacker observing verification timing can iteratively determine the correct HMAC value, enabling JWS signature forgery for HS256, HS384, and HS512 algorithms.

**Impact:** JWS tokens signed with HMAC algorithms can be forged by an attacker who can submit tokens and measure verification timing.

**Recommendation:** Replace `===` with `hash_equals()`:

```php
return hash_equals($this->digest($key, $message), $digest);
```

---

### Finding 3: Private Key Material Leaked in Exception Messages (HIGH)

**Severity:** HIGH
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
**Files:**
- `src/security/rsa/_AbstractRSAKeyPEMFormat.php:72`
- `src/security/rsa/_RSAPrivateKeyPEMFormat.php:39`

**Description:**
When PEM parsing fails, the full PEM-encoded key material is included in the exception message:

```php
// _AbstractRSAKeyPEMFormat.php:72
throw new RSABadPEMFormat(sprintf('pem %s', $pem_format));

// _RSAPrivateKeyPEMFormat.php:39
throw new RSABadPEMFormat(sprintf('pem %s is a public key!', $pem_format));
```

If these exceptions are caught and logged (or displayed in error responses), the full private key PEM is exposed. Even if the key was malformed, partial key material may still be sensitive.

**Impact:** Private key material can end up in log files, error monitoring systems (Sentry, Datadog, etc.), or HTTP error responses. Any system that captures exception messages will record the full PEM content.

**Recommendation:** Remove key material from exception messages. Use a generic message:

```php
throw new RSABadPEMFormat('Failed to parse PEM key');
throw new RSABadPEMFormat('PEM contains a public key, expected private key');
```

---

### Finding 4: RSA PKCS#1 v1.5 Key Transport — Inherent Protocol Risk (MEDIUM)

**Severity:** MEDIUM
**CWE:** CWE-780 (Use of RSA Algorithm without OAEP)
**File:** `src/jwa/cryptographic_algorithms/key_management/rsa/PKCS1/RSA1_5_KeyManagementAlgorithm.php`

**Description:**
The library supports `RSA1_5` (RSAES-PKCS1-v1_5) for key encryption, which is inherently vulnerable to Bleichenbacher-style padding oracle attacks. While phpseclib 3.x implements timing-safe PKCS1v1.5 decryption internally, the protocol itself is considered deprecated by RFC 7516 Section 4.1:

> "A key of size 2048 bits or larger MUST be used with this algorithm. This algorithm is defined for compatibility only and is NOT RECOMMENDED for new deployments."

The JOSE4PHP error handling in `RSA_KeyManagementAlgorithm::decrypt()` (line 70-93) correctly delegates to phpseclib, which handles padding oracle mitigations internally. However, the exception-based flow (`catch (\Exception $e)`) could leak timing information if phpseclib throws differently for padding vs. other failures.

**Impact:** The RSA1_5 algorithm has known cryptographic weaknesses. phpseclib 3.x mitigates the worst padding oracle issues, but the protocol remains fundamentally less secure than OAEP. **Note:** phpseclib's padding oracle mitigations are claimed by its documentation but were not independently verified (via code inspection or timing test harness) as part of this audit.

**Recommendation:**
1. Add a deprecation notice/log warning when RSA1_5 is used
2. Document that RSA-OAEP or RSA-OAEP-256 should be preferred for new deployments
3. Consider making RSA1_5 opt-in rather than registered by default in a future major version

---

### Finding 5: No Key Material Zeroing After Use (MEDIUM)

**Severity:** MEDIUM
**CWE:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
**Files:**
- `src/security/SymmetricSharedKey.php` — `$secret` property never cleared
- `src/security/rsa/_AbstractRSAKeyPEMFormat.php` — `$pem_format`, `$password` properties never cleared
- `src/security/rsa/_RSAPrivateKeyPEMFormat.php` — `$d` (private exponent) never cleared
- `src/jwe/impl/_ContentEncryptionKey.php` — CEK value never cleared
- `src/jwa/cryptographic_algorithms/content_encryption/AES_CBC_HS/AES_CBC_HMAC_SHA2_Algorithm.php` — `$mac_key`, `$enc_key` local variables not zeroed after use

**Description:**
No class in the library implements a destructor or cleanup method to zero sensitive key material from memory. Private keys, shared secrets, CEKs, and passwords persist in PHP memory until garbage collected. In long-running processes (PHP-FPM, ReactPHP, Swoole), key material may remain in memory indefinitely.

Additionally, local variables holding split key material (`$mac_key`, `$enc_key` in AES-CBC-HMAC encrypt/decrypt) are never zeroed after the cryptographic operation completes.

**Impact:** In long-running PHP processes or when memory is dumped (crash dumps, core dumps, swap files), key material is recoverable. In traditional PHP-CGI request lifecycles, the risk is lower since memory is released per-request.

**Recommendation:**
1. Add `sodium_memzero()` calls (available since PHP 7.2 via libsodium) to clear sensitive variables after use
2. Implement `__destruct()` on key classes to zero stored key material
3. Zero local variables (`$mac_key`, `$enc_key`) in AES-CBC-HMAC operations after use:
   ```php
   sodium_memzero($mac_key);
   sodium_memzero($enc_key);
   ```

**Note:** PHP's garbage collector does not guarantee timely memory clearing. `sodium_memzero()` overwrites the variable's memory immediately. If the `sodium` extension is unavailable, a polyfill using `str_repeat("\0", strlen($var))` provides partial protection.

---

### Finding 6: Password Stored in Plaintext in Key Objects (MEDIUM)

**Severity:** MEDIUM
**CWE:** CWE-256 (Plaintext Storage of a Password)
**File:** `src/security/rsa/_AbstractRSAKeyPEMFormat.php:37,64-66`

**Description:**
When a password-protected private key is loaded, the password is stored as a plaintext property on the key object for the lifetime of the object:

```php
protected $password;

if(!empty($password)) {
    $this->password = trim($password);
}
```

The password is accessible via `getPassword()` and `hasPassword()` methods. After the key has been loaded by phpseclib (`PublicKeyLoader::load()`), the password serves no further purpose but remains in memory.

**Impact:** The password persists in the key object unnecessarily. If the object is serialized, logged, or dumped, the password is exposed.

**Recommendation:** Clear the password after successful key loading:

```php
try {
    $loaded_key = PublicKeyLoader::load($this->pem_format, $this->password ?? false);
    $this->key = new CustomAsymmetricKey($loaded_key);
    // Password no longer needed - clear it
    if ($this->password !== null) {
        sodium_memzero($this->password);
    }
    $this->password = null;
} catch (\Exception $e) { ... }
```

**Caveat:** If `getPassword()` is used downstream (e.g., `RSA_Algorithm::sign()` at line 48 re-reads the password), this change requires verifying all callers. Currently, `sign()` reads the password to pass to `PublicKeyLoader::load()`, but it already has the loaded key — the password is only needed once during construction.

---

### Finding 7: Broad Exception Catching in Crypto Operations (LOW)

**Severity:** LOW
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
**Files:**
- `src/jwa/cryptographic_algorithms/digital_signatures/rsa/RSA_Algorithm.php:50-54,78-82`
- `src/jwa/cryptographic_algorithms/key_management/rsa/RSA_KeyManagementAlgorithm.php:50-52,78-83`

**Description:**
Crypto operations catch `\Exception` broadly and convert all failures to `InvalidKeyTypeAlgorithmException`:

```php
try {
    $key = PublicKeyLoader::load($private_key->getEncoded(), $password);
} catch (\Exception $e) {
    throw new InvalidKeyTypeAlgorithmException;
}
```

This masks the actual failure reason. While this is actually beneficial from a security perspective (it prevents information leakage about why key loading failed), it makes debugging legitimate key format issues difficult. The original exception's message is discarded.

**Impact:** Low direct security impact. The broad catch is somewhat security-positive (prevents oracle attacks through differentiated error messages). However, it complicates debugging and could mask unexpected runtime errors.

**Recommendation:** Consider logging the original exception at DEBUG level (not in production) while keeping the generic exception thrown to callers. Use `previous` exception chaining:

```php
throw new InvalidKeyTypeAlgorithmException('could not load key', 0, $e);
```

This preserves the chain for debugging without changing the public error surface.

---

### Finding 8: phpseclib 3.x Integration — Secure Defaults Verified (INFORMATIONAL)

**Severity:** INFORMATIONAL (Positive Finding)
**Files:**
- `src/jwa/cryptographic_algorithms/key_management/rsa/OAEP/RSA_OAEP_KeyManagementAlgorithm.php`
- `src/jwa/cryptographic_algorithms/key_management/rsa/OAEP/RSA_OAEP_256_KeyManagementAlgorithm.php`
- `src/jwa/cryptographic_algorithms/key_management/rsa/PKCS1/RSA1_5_KeyManagementAlgorithm.php`
- `src/jwa/cryptographic_algorithms/digital_signatures/rsa/PKCS1/RSASSA_PKCS1_v1_5_Algorithm.php`
- `src/jwa/cryptographic_algorithms/digital_signatures/rsa/PSS/RSASSA_PSS_Algorithm.php`

**Description:**
The phpseclib 3.x integration uses correct padding mode constants and configurations:

| Algorithm | Padding Constant | Hash | MGF Hash | Status |
|-----------|-----------------|------|----------|--------|
| RSA1_5 | `RSA::ENCRYPTION_PKCS1` | sha1 | sha1 | Correct per RFC 7518 |
| RSA-OAEP | `RSA::ENCRYPTION_OAEP` | sha1 | sha1 | Correct per RFC 7518 §4.3 |
| RSA-OAEP-256 | `RSA::ENCRYPTION_OAEP` | sha256 | sha256 | Correct per RFC 7518 §4.3 |
| RS256/384/512 | `RSA::SIGNATURE_PKCS1` | sha256/384/512 | sha256/384/512 | Correct |
| PS256/384/512 | `RSA::SIGNATURE_PSS` | sha256/384/512 | sha256/384/512 | Correct |

All RSA operations enforce a 2048-bit minimum key length via `Abstract_RSA_Algorithm::getMinKeyLen()`.

---

### Finding 9: CSPRNG Usage Verified (INFORMATIONAL)

**Severity:** INFORMATIONAL (Positive Finding)
**Files:**
- `src/utils/ByteUtil.php:33-35`
- `src/jwe/impl/IVFactory.php`
- `src/jwe/impl/ContentEncryptionKeyFactory.php`

**Description:**
All random byte generation flows through `ByteUtil::randomBytes()` which delegates to `phpseclib3\Crypt\Random::string()`. This uses PHP's CSPRNG (`random_bytes()` on PHP 7+). The chain is:

```
IVFactory::build() → RandomNumberGeneratorService → ByteUtil::randomBytes() → Random::string()
ContentEncryptionKeyFactory::build() → RandomNumberGeneratorService → ByteUtil::randomBytes() → Random::string()
```

IV sizes are correctly set (128-bit for AES-CBC). CEK sizes match the content encryption algorithm requirements. No use of `rand()`, `mt_rand()`, or other weak PRNGs was found.

---

## Findings Summary

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | Non-constant-time AES-CBC-HMAC tag comparison | **CRITICAL** | CWE-208 |
| 2 | Non-constant-time HMAC signature verification | **CRITICAL** | CWE-208 |
| 3 | Private key material in exception messages | **HIGH** | CWE-209 |
| 4 | RSA PKCS#1 v1.5 inherent protocol risk | MEDIUM | CWE-780 |
| 5 | No key material zeroing after use | MEDIUM | CWE-226 |
| 6 | Password stored in plaintext in key objects | MEDIUM | CWE-256 |
| 7 | Broad exception catching in crypto ops | LOW | CWE-755 |
| 8 | phpseclib 3.x secure defaults verified | INFO | — |
| 9 | CSPRNG usage verified | INFO | — |

**Critical: 2 | High: 1 | Medium: 3 | Low: 1 | Informational: 2**

## Progress Tracking

This is a findings-only report. No implementation tasks.

- [x] Task 1: Explore AES-CBC-HMAC-SHA2 implementation
- [x] Task 2: Explore RSA key management algorithms
- [x] Task 3: Explore RSA digital signature algorithms
- [x] Task 4: Explore key material handling and storage
- [x] Task 5: Explore IV/CEK generation and RNG chain
- [x] Task 6: Explore HMAC signature verification
- [x] Task 7: Explore JWE encryption/decryption flow
- [x] Task 8: Explore error handling and exception messages
- [x] Task 9: Write findings report

**Total Tasks:** 9 | **Completed:** 9 | **Remaining:** 0
