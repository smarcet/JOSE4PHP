<?php namespace jwa\cryptographic_algorithms\content_encryption;
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
use jwa\cryptographic_algorithms\exceptions\InvalidAuthenticationTagException;
use jwa\cryptographic_algorithms\HashFunctionAlgorithm;
/**
 * Interface ContentEncryptionAlgorithm
 * @package jwa\cryptographic_algorithms\content_encryption
 */
interface ContentEncryptionAlgorithm extends HashFunctionAlgorithm
{

    /**
     * https://tools.ietf.org/html/rfc7518#section-5.2.2.1
     *
     * @param string $plain_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @return string[]
     */
     public function encrypt($plain_text, $key, $iv, $aad);

    /**
     * https://tools.ietf.org/html/rfc7518#section-5.2.2.2
     *
     * @param string $cypher_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @param string $tag
     * @return string
     * @throws InvalidAuthenticationTagException
     */
    public function decrypt($cypher_text, $key, $iv, $aad, $tag);

    /**
     * @return int|null
     */
    public function getIVSize();

    /**
     * @return int
     */
    public function getCEKSize();
}