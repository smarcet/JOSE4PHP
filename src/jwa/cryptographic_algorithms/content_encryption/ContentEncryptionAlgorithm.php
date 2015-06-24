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

namespace jwa\cryptographic_algorithms\content_encryption;

use jwa\cryptographic_algorithms\HashFunctionAlgorithm;

/**
 * Interface ContentEncryptionAlgorithm
 * @package jwa\cryptographic_algorithms\content_encryption
 */
interface ContentEncryptionAlgorithm extends HashFunctionAlgorithm {

    /**
     * Encrypt data.
     *
     * @param string      $data                     The data to encrypt
     * @param string      $cek                      The content encryption key
     * @param string      $iv                       The Initialization Vector
     * @param string|null $aad                      Additional Additional Authenticated Data
     * @param string      $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string      $tag                      Tag
     *
     * @return string The encrypted data
     */
    public function encryptContent($data, $cek, $iv, $aad, $encoded_protected_header, &$tag);

    /**
     * Decrypt data.
     *
     * @param string      $data                     The data to decrypt
     * @param string      $cek                      The content encryption key
     * @param string      $iv                       The Initialization Vector
     * @param string|null $aad                      Additional Additional Authenticated Data
     * @param string      $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string      $tag                      Tag
     *
     * @return string
     */
    public function decryptContent($data, $cek, $iv, $aad, $encoded_protected_header, $tag);

    /**
     * @return int|null
     */
    public function getIVSize();

    /**
     * @return int
     */
    public function getCEKSize();
}