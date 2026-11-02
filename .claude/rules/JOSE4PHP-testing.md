# Testing Conventions

## Test Structure

- Tests live in `tests/` (flat directory, one file per JOSE module)
- All test classes extend `\PHPUnit\Framework\TestCase`
- Test classes are `final class`

| File | Covers |
|------|--------|
| `JsonWebTokenTest.php` | JWT claims, serialization, unsecured JWT |
| `JsonWebSignatureTest.php` | JWS sign/verify (HS256/384/512, RS256/384/512, PS256/384/512) |
| `JsonWebEncryptionTest.php` | JWE encrypt/decrypt |
| `JsonWebKeyTest.php` | JWK creation, RSA/Octet key specs |
| `JsonWebAlgorithmsTest.php` | Algorithm registry lookups |

## Test Keys

`TestKeys.php` holds static PEM keys for tests:
- `$private_key_pem` / `$public_key_pem` — RSA key pair (no password)
- `$private_key2_pem` / `$public_key2_pem` — second RSA key pair
- `$private_key_with_pass_rs256` — password-protected RSA private key

**IMPORTANT:** These are test-only keys committed to the repo. Never use them in production.

## Running Tests

```bash
vendor/bin/phpunit                    # full suite
vendor/bin/phpunit --filter testName  # single test
```

## Patterns

- Tests use PHPUnit's `#[Depends]` attribute to chain test methods (e.g., build claim set → build JWS → verify JWS)
- Shared state via `static` properties and `setUpBeforeClass()`
- Test methods return values that are passed as parameters to dependent tests
- No mocking of internal classes — tests exercise real crypto operations
