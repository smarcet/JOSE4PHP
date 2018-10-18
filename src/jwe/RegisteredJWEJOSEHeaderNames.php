<?php namespace jwe;
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
use jwt\RegisteredJOSEHeaderNames;
use utils\json_types\JsonTypes;
/**
 * Class RegisteredJWEJOSEHeaderNames
 * @package jwe
 *
 * https://tools.ietf.org/html/rfc7516#section-4.1
 */
abstract class RegisteredJWEJOSEHeaderNames extends RegisteredJOSEHeaderNames {

    /**
     * @mandatory
     *
     * https://tools.ietf.org/html/rfc7516#section-4.1.2
     *
     * The "enc" (encryption algorithm) Header Parameter identifies the
     * content encryption algorithm used to perform authenticated encryption
     * on the plaintext to produce the ciphertext and the Authentication
     * Tag.  This algorithm MUST be an AEAD algorithm with a specified key
     * length.  The encrypted content is not usable if the "enc" value does
     * not represent a supported algorithm.  "enc" values should either be
     * registered in the IANA "JSON Web Signature and Encryption Algorithms"
     * registry established by [JWA] or be a value that contains a
     * Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
     * string containing a StringOrURI value.  This Header Parameter MUST be
     * present and MUST be understood and processed by implementations.
     */
    const EncryptionAlgorithm = 'enc';

    /**
     * @optional
     *
     * https://tools.ietf.org/html/rfc7516#section-4.1.3
     *
     * The "zip" (compression algorithm) applied to the plaintext before
     * encryption, if any.  The "zip" value defined by this specification
     * is:
     * o  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
     * Other values MAY be used.  Compression algorithm values can be
     * registered in the IANA "JSON Web Encryption Compression Algorithms"
     * registry established by [JWA].  The "zip" value is a case-sensitive
     * string.  If no "zip" parameter is present, no compression is applied
     * to the plaintext before encryption.  When used, this Header Parameter
     * MUST be integrity protected; therefore, it MUST occur only within the
     * JWE Protected Header.  Use of this Header Parameter is OPTIONAL.
     */
    const CompressionAlgorithm = 'zip';


    public static $registered_basic_headers_set = array (
        self::Algorithm,
        self::EncryptionAlgorithm,
        self::KeyID,
        self::CompressionAlgorithm,
        self::Type,
        self::ContentType,
    );

    public static $registered_basic_headers_set_types = array (
        self::Algorithm            => JsonTypes::StringOrURI ,
        self::Type                 => JsonTypes::StringOrURI,
        self::ContentType          => JsonTypes::StringOrURI,
        self::KeyID                => JsonTypes::JsonValue,
        self::EncryptionAlgorithm  => JsonTypes::StringOrURI,
        self::CompressionAlgorithm => JsonTypes::JsonValue,
    );
}