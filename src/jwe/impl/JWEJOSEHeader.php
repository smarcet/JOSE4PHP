<?php
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

namespace jwe\impl;

use jwe\IEncJOSEHeader;
use jwe\RegisteredJWEJOSEHeaderNames;
use jwt\impl\JOSEHeader;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;

/**
 * Class JWEJOSEHeader
 * @package jwe\impl
 */
final class JWEJOSEHeader
    extends JOSEHeader implements
    IEncJOSEHeader {

    /**
     * @param StringOrURI $alg
     * @param StringOrURI $enc
     * @param StringOrURI $type
     * @param StringOrURI $cty
     * @param JsonValue $kid
     */
    public function __construct(StringOrURI $alg, StringOrURI $enc, StringOrURI $type = null, StringOrURI $cty = null, JsonValue  $kid = null){
        parent::__construct($alg,$type,$cty, $kid);
        $this->set[RegisteredJWEJOSEHeaderNames::EncryptionAlgorithm] = $enc;
    }

    /**
     * @mandatory
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
     *
     * @return StringOrURI
     */
    public function getEncryptionAlgorithm()
    {
        return $this[RegisteredJWEJOSEHeaderNames::EncryptionAlgorithm];
    }
}