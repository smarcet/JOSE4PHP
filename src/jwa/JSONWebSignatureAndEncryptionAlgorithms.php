<?php namespace jwa;
/**
 * Copyright 2015 OpenStack Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

/**
 * Class JSONWebSignatureAndEncryptionAlgorithms
 * @package jwa
 *
 * https://tools.ietf.org/html/rfc7518#page-33
 */
abstract class JSONWebSignatureAndEncryptionAlgorithms {

    // Cryptographic Algorithms for Digital Signatures and MACs
    // https://tools.ietf.org/html/rfc7518#section-3

    // HMAC with SHA-2 Functions

    /**
     * HMAC using SHA-256
     */
    const HS256 = 'HS256';

    /**
     * HMAC using SHA-384
     */
    const HS384 = 'HS384';

    /**
     * HMAC using SHA-512
     */
    const HS512 = 'HS512';

    // Digital Signature with RSASSA-PKCS1-v1_5

    /**
     *  RSASSA-PKCS1-v1_5 using SHA-256
     */
    const RS256 = 'RS256';

    /**
     * RSASSA-PKCS1-v1_5 using SHA-384
     */
    const RS384 = 'RS384';

    /**
     * RSASSA-PKCS1-v1_5 using SHA-512
     */
    const RS512 = 'RS512';

    // Digital Signature with ECDSA

    /**
     *  ECDSA using P-256 and SHA-256
     */
    const ES256 = 'ES256';

    /**
     *  ECDSA using P-384 and SHA-384
     */
    const ES384 = 'ES384';

    /**
     * ECDSA using P-521 and SHA-512
     */
    const ES512 = 'ES512';

    // Digital Signature with RSASSA-PSS

    /**
     *  RSASSA-PSS using SHA-256 and MGF1 with SHA-256
     */
    const PS256 = 'PS256';

    /**
     *  RSASSA-PSS using SHA-384 and MGF1 with SHA-384
     */
    const PS384 = 'PS384';

    /**
     *  RSASSA-PSS using SHA-512 and MGF1 with SHA-512
     */
    const PS512 = 'PS512';

    /**
     *   No digital signature or MAC performed
     */
    const None = 'none';

    // Cryptographic Algorithms for Key Management
    // https://tools.ietf.org/html/rfc7518#section-4

    /**
     *  RSAES-PKCS1-v1_5
     */
    const RSA1_5 = 'RSA1_5';

    /**
     *   RSAES OAEP using default parameters
     */
    const RSA_OAEP = 'RSA-OAEP';

    /**
     *  RSAES OAEP using SHA-256 and MGF1 with SHA-256
     */
    const RSA_OAEP_256 = 'RSA-OAEP-256';

    /**
     * AES Key Wrap using 128-bit key
     */
    const A128KW = 'A128KW';

    /**
     *  AES Key Wrap using 192-bit key
     */
    const A192KW = 'A192KW';

    /**
     *  AES Key Wrap using 256-bit key
     */
    const A256KW= 'A256KW';

    /**
     *   Direct use of a shared symmetric key
     */
    const Dir = 'dir';

    /**
     * ECDH-ES using Concat KDF
     */
    const ECDH_ES = 'ECDH-ES';

    /**
     *  ECDH-ES using Concat KDF and "A128KW" wrapping
     */
    const ECDH_ES_A128KW = 'ECDH-ES+A128KW';

    /**
     *  ECDH-ES using Concat KDF and "A192KW" wrapping
     */
    const ECDH_ES_A192KW = 'ECDH-ES+A192KW';

    /**
     * ECDH-ES using Concat KDF and "A256KW" wrapping
     */
    const ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    /**
     *  Key wrapping with AES GCM using 128-bit key
     */
    const A128GCMKW = 'A128GCMKW';

    /**
     * Key wrapping with AES GCM using 192-bit key
     */
    const A192GCMKW = 'A192GCMKW';

    /**
     * Key wrapping with AES GCM using 256-bit key
     */
    const A256GCMKW = 'A256GCMKW';

    /**
     * PBES2 with HMAC SHA-256 and "A128KW" wrapping
     */
    const PBES2_HS256_A128KW = 'PBES2-HS256+A128KW';

    /**
     *  PBES2 with HMAC SHA-384 and "A192KW" wrapping
     */
    const PBES2_HS384_A192KW = 'PBES2-HS384+A192KW';

    /**
     *  PBES2 with HMAC SHA-512 and "A256KW" wrapping
     */
    const PBES2_HS512_A256KW = 'PBES2-HS512+A256KW';

    /**
     *  AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
     */
    const A128CBC_HS256 = 'A128CBC-HS256';

    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
     */
    const A192CBC_HS384 = 'A192CBC-HS384';

    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
     */
    const A256CBC_HS512 = 'A256CBC-HS512';

    /**
     * AES GCM using 128-bit key
     */
    const A128GCM = 'A128GCM';

    /**
     * AES GCM using 192-bit key
     */
    const A192GCM = 'A192GCM';

    /**
     * AES GCM using 256-bit key
     */
    const A256GCM = 'A256GCM';

    public static $header_location_alg = [

        self::HS256,
        self::HS384,
        self::HS512,
        self::RS256,
        self::RS384,
        self::RS512,
        self::ES256 ,
        self::ES384,
        self::ES512 ,
        self::PS256,
        self::PS384 ,
        self::PS512,
        self::None,
        self::RSA1_5,
        self::RSA_OAEP ,
        self::RSA_OAEP_256,
        self::A128KW ,
        self::A192KW,
        self::A192KW,
        self::A256KW,
        self::Dir,
        self::ECDH_ES,
        self::ECDH_ES_A128KW ,
        self::ECDH_ES_A192KW,
        self::ECDH_ES_A256KW ,
        self::A128GCMKW ,
        self::A192GCMKW,
        self::A256GCMKW ,
        self::PBES2_HS256_A128KW ,
        self::PBES2_HS384_A192KW,
        self::PBES2_HS512_A256KW,
    ];

    public static $header_location_enc = [
        self::A128CBC_HS256,
        self::A192CBC_HS384,
        self::A256CBC_HS512,
        self::A128GCM,
        self::A192GCM,
        self::A256GCM,
    ];

}