<?php namespace jwa\cryptographic_algorithms\key_management;
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
use jwa\cryptographic_algorithms\EncryptionAlgorithm;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyTypeAlgorithmException;
use jwa\cryptographic_algorithms\key_management\modes\DirectEncryption;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwk\JSONWebKeyTypes;
use security\Key;
/**
 * Class DirAlgorithm
 * @package jwa\cryptographic_algorithms\key_management
 */
final class DirAlgorithm implements EncryptionAlgorithm, DirectEncryption
{

    /**
     * @param Key $key
     * @param $message
     * @return string
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function encrypt(Key $key, $message)
    {
        return $message;
    }

    /**
     * @param Key $key
     * @param string $enc_message
     * @return string
     */
    public function decrypt(Key $key, $enc_message)
    {
       return $enc_message;
    }

    /**
     * @return string
     */
    public function getHashingAlgorithm()
    {
       return null;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return JSONWebSignatureAndEncryptionAlgorithms::Dir;
    }

    /**
     * @return string
     */
    public function getKeyType()
    {
        return JSONWebKeyTypes::OctetSequence;
    }

    /**
     * unit is on bits
     * @return int
     */
    public function getMinKeyLen()
    {
        return 256;
    }

    /**
     * hash key size in bits
     * @return int
     */
    public function getHashKeyLen()
    {
        return $this->getMinKeyLen();
    }
}