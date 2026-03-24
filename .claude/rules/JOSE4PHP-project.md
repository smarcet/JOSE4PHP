# Project: JOSE4PHP

**Last Updated:** 2026-03-24

## Overview

PHP library implementing the JOSE (JSON Object Signing and Encryption) suite of RFCs:
- JWT (RFC 7519), JWS (RFC 7515), JWE (RFC 7516), JWK (RFC 7517), JWA (RFC 7518)

## Technology Stack

- **Language:** PHP ^8.3
- **Crypto:** phpseclib 3.x (native API, no compat layer)
- **Testing:** PHPUnit 9/10/11, Mockery 1.6
- **Autoload:** Composer classmap (no PSR-4)
- **CI:** GitHub Actions (PHP 8.3, extensions: mbstring, exif, pcntl, bcmath, sockets, gettext, crypto, gmp, zlib, json)

## Directory Structure

```
src/
├── jwa/          # JSON Web Algorithms — registries + algorithm implementations
├── jwe/          # JSON Web Encryption — encrypt/decrypt, JOSE headers, compression
├── jwk/          # JSON Web Key — key types (RSA, Octet), specs, factories
├── jws/          # JSON Web Signature — sign/verify
├── jwt/          # JSON Web Token — claims, headers, serialization
├── security/     # Key primitives (KeyPair, PrivateKey, PublicKey, SharedKey, x509)
└── utils/        # Base64url, ByteUtil, JSON types, factories, services
tests/            # PHPUnit test suite (flat, one file per module)
bootstrap/        # Composer autoload bootstrap
```

## Key Entry Points

- `utils\factories\BasicJWTFactory::build($compact)` — parses any compact serialization (JWS/JWE/unsecured JWT)
- `jws\JWSFactory::build($spec)` — creates JWS from spec
- `jwe\impl\JWEFactory::build($spec)` — creates JWE from spec

## Development Commands

| Task | Command |
|------|---------|
| Install | `composer install` |
| Run tests | `vendor/bin/phpunit` |
| Autoload dump | `composer dump-autoload --optimize` |

## Architecture Notes

- **Classmap autoloading** — namespaces map to directory structure (`jwa\` → `src/jwa/`) but autoload is classmap-based, not PSR-4
- **Singleton registries** — algorithm lookup via `*_Registry::getInstance()->get($alg)` (see `DigitalSignatures_MACs_Registry`, `KeyManagementAlgorithms_Registry`, `ContentEncryptionAlgorithms_Registry`)
- **Specification pattern** — JWS/JWE creation uses spec objects (`IJWS_Specification`, `IJWE_Specification`) with compact-format and params variants
- **phpseclib 3.x** — uses native API (migrated from 2.x, compat layer removed)
