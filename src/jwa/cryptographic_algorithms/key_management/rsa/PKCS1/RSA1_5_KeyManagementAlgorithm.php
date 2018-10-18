<?php namespace jwa\cryptographic_algorithms\key_management\rsa\PKCS1;
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
use jwa\cryptographic_algorithms\key_management\rsa\RSA_KeyManagementAlgorithm;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use phpseclib\Crypt\RSA;
/**
 * Class RSA1_5_KeyManagementAlgorithm
 * @package jwa\cryptographic_algorithms\key_management\rsa\PKCS1
 */
final class RSA1_5_KeyManagementAlgorithm extends RSA_KeyManagementAlgorithm
{

    /**
     * @return string
     */
    public function getHashingAlgorithm()
    {
        return 'sha1';
    }

    /**
     * @return string
     */
    public function getName()
    {
        return JSONWebSignatureAndEncryptionAlgorithms::RSA1_5;
    }

    /**
     * @return int
     */
    public function getEncryptionMode()
    {
        return RSA::ENCRYPTION_PKCS1;
    }

    /**
     * @return string
     */
    public function getMGFHash()
    {
        return $this->getHashingAlgorithm();
    }

    /**
     * hash key size in bits
     * @return int
     */
    public function getHashKeyLen()
    {
        return 1;
    }
}