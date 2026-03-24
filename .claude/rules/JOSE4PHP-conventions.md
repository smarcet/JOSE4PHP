# Coding Conventions

## Namespaces

Namespaces are lowercase, matching directory structure under `src/`:

```
jwa\                                    → src/jwa/
jwa\cryptographic_algorithms\           → src/jwa/cryptographic_algorithms/
jwe\impl\                               → src/jwe/impl/
jwk\impl\                               → src/jwk/impl/
jws\impl\                               → src/jws/impl/
jwt\impl\                               → src/jwt/impl/
utils\factories\                        → src/utils/factories/
security\rsa\                           → src/security/rsa/
```

No `App\` or vendor prefix — namespaces start at the JOSE module level.

## Class Conventions

- **Interfaces** prefixed with `I` (e.g., `IJWK`, `IJWS`, `IBasicJWT`)
- **Implementations** are `final class` — not designed for extension
- **Constants/enums** use `abstract class` with static properties (e.g., `JSONWebKeyTypes`, `KeyManagementModeValues`)
- **Registries** are singletons with `getInstance()` pattern
- **Factories** are `final class` with `static public function build($spec)`
- **Exceptions** live in `exceptions/` subdirectories within each module

## Specification Pattern

JWS and JWE creation uses specification objects instead of raw constructor args:

```php
// Compact format (parsing existing token)
$spec = new JWS_CompactFormatSpecification($compact_serialization);
$jws = JWSFactory::build($spec);

// Params (creating new token)
$spec = new JWS_ParamsSpecification($alg, $jwk, $payload);
$jws = JWSFactory::build($spec);
```

## Algorithm Registration

Algorithms are registered in singleton registries, keyed by JWA algorithm name string:
- `DigitalSignatures_MACs_Registry` — HS256/384/512, RS256/384/512, PS256/384/512
- `KeyManagementAlgorithms_Registry` — RSA-OAEP, RSA1_5, dir, A128KW/A192KW/A256KW
- `ContentEncryptionAlgorithms_Registry` — A128CBC-HS256, A192CBC-HS384, A256CBC-HS512

To add a new algorithm: create the implementation class, register it in the relevant `*_Registry` constructor.

## JSON Types

Custom value objects in `utils\json_types\`:
- `StringOrURI` — string that may be a URI
- `NumericDate` — integer epoch timestamp
- `JsonValue` — generic JSON value

Used for type-safe JWT claims and JOSE header parameters.

## License Header

All PHP files include the Apache 2.0 license header (OpenStack Foundation copyright).

**Note:** `composer.json` declares MIT license — source file headers use Apache 2.0. Follow the Apache 2.0 header convention in source files.
