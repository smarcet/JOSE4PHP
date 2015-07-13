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

namespace jwk;
use jwk\exceptions\JWKInvalidIdentifierException;

/**
 * Interface IJWKSet
 * @package jwk
 *
 * https://tools.ietf.org/html/rfc7517#section-5
 *
 * A JWK Set is a JSON object that represents a set of JWKs.  The JSON
 * object MUST have a "keys" member, with its value being an array of
 * JWKs.  This JSON object MAY contain whitespace and/or line breaks.
 * The member names within a JWK Set MUST be unique; JWK Set parsers
 * MUST either reject JWK Sets with duplicate member names or use a JSON
 * parser that returns only the lexically last duplicate member name, as
 * specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
 * [ECMAScript].
 * Additional members can be present in the JWK Set; if not understood
 * by implementations encountering them, they MUST be ignored.
 * Parameters for representing additional properties of JWK Sets should
 * either be registered in the IANA "JSON Web Key Set Parameters"
 * registry established by Section 8.4 or be a value that contains a
 * Collision-Resistant Name.
 * Implementations SHOULD ignore JWKs within a JWK Set that use "kty"
 * (key type) values that are not understood by them, that are missing
 * required members, or for which values are out of the supported
 * ranges.
 */
interface IJWKSet {

    /**
     * @return IJWK[]
     */
    public function getKeys();

    /**
     * @param IJWK $key
     * @return void
     * @throws JWKInvalidIdentifierException
     */
    public function addKey(IJWK $key);

    /**
     * @param string $kid
     * @return IJWK
     */
    public function getKeyById($kid);

    // factory methods

    /**
     * @param $json
     * @return IJWKSet
     */
    static public function fromJson($json);

}