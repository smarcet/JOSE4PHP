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
use jwa\cryptographic_algorithms\key_management\DirAlgorithm;
use jwa\cryptographic_algorithms\key_management\rsa\OAEP\RSA_OAEP_256_KeyManagementAlgorithm;
use jwa\cryptographic_algorithms\key_management\rsa\OAEP\RSA_OAEP_KeyManagementAlgorithm;
use jwa\cryptographic_algorithms\key_management\rsa\PKCS1\RSA1_5_KeyManagementAlgorithm;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
/**
 * Class KeyManagementAlgorithms_Registry
 * @package jwa\cryptographic_algorithms
 */
final class KeyManagementAlgorithms_Registry
{

    /**
     * @var KeyManagementAlgorithms_Registry
     */
    private static $instance;

    private $algorithms = [];

    private function __construct()
    {

        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RSA1_5] = new RSA1_5_KeyManagementAlgorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP] = new RSA_OAEP_KeyManagementAlgorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP_256] = new RSA_OAEP_256_KeyManagementAlgorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::Dir] = new DirAlgorithm;
    }

    private function __clone(){}

    /**
     * @return KeyManagementAlgorithms_Registry
     */
    public static function getInstance()
    {
        if(!is_object(self::$instance))
        {
            self::$instance = new KeyManagementAlgorithms_Registry();
        }
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return bool
     */
    public function isSupported($alg)
    {
        return array_key_exists($alg, $this->algorithms);
    }

    /**
     * @param $alg
     * @return null|EncryptionAlgorithm
     */
    public function get($alg)
    {
        if(!$this->isSupported($alg)) return null;
        return $this->algorithms[$alg];
    }
}