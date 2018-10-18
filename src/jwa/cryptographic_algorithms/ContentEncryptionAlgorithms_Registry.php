<?php namespace jwa\cryptographic_algorithms;
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
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A128CBCHS256_Algorithm;
use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A192CBCHS384_Algorithm;
use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A256CBCHS512_Algorithm;
use jwa\cryptographic_algorithms\content_encryption\ContentEncryptionAlgorithm;
/**
 * Class ContentEncryptionAlgorithms_Registry
 * @package jwa\cryptographic_algorithms
 */
final class ContentEncryptionAlgorithms_Registry
{

    /**
     * @var ContentEncryptionAlgorithms_Registry
     */
    private static $instance;

    private $algorithms = array();

    private function __construct()
    {

        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256] = new A128CBCHS256_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::A192CBC_HS384] = new A192CBCHS384_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512] = new A256CBCHS512_Algorithm;
    }

    private function __clone() {}

    /**
     * @return ContentEncryptionAlgorithms_Registry
     */
    public static function getInstance() {
        if (!is_object(self::$instance)) {
            self::$instance = new ContentEncryptionAlgorithms_Registry();
        }
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return bool
     */
    public function isSupported($alg) {
        return array_key_exists($alg, $this->algorithms);
    }

    /**
     * @param $alg
     * @return null|ContentEncryptionAlgorithm
     */
    public function get($alg) {
        if (!$this->isSupported($alg)) return null;
        return $this->algorithms[$alg];
    }
}