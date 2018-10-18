<?php namespace jwa\cryptographic_algorithms\key_management\rsa;
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
use jwa\cryptographic_algorithms\Abstract_RSA_Algorithm;
use jwa\cryptographic_algorithms\EncryptionAlgorithm;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyTypeAlgorithmException;
use jwa\cryptographic_algorithms\key_management\modes\KeyEncryption;
use security\Key;
use security\rsa\RSAPrivateKey;
use security\rsa\RSAPublicKey;
/**
 * Class RSA_KeyManagementAlgorithm
 * @package jwa\cryptographic_algorithms\key_management\rsa
 */
abstract class RSA_KeyManagementAlgorithm
    extends Abstract_RSA_Algorithm
    implements EncryptionAlgorithm, KeyEncryption {

    public function __construct(){

        parent::__construct();
        //configuration ...
        $this->rsa_impl->setEncryptionMode($this->getEncryptionMode());
        $this->rsa_impl->setHash($this->getHashingAlgorithm());
        $this->rsa_impl->setMGFHash($this->getMGFHash());
    }

    /**
     * @param Key $key
     * @param $message
     * @return string
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function encrypt(Key $key, $message)
    {
        if(!($key instanceof RSAPublicKey))
            throw new InvalidKeyTypeAlgorithmException('key is not public');

        if($key->getFormat() !== 'PKCS8')
            throw new InvalidKeyTypeAlgorithmException('keys is not on PKCS1 format');

        $res = $this->rsa_impl->loadKey($key->getEncoded());

        if(!$res)
            throw new InvalidKeyTypeAlgorithmException('could not parse the key');

        if($this->rsa_impl->getSize() < $this->getMinKeyLen())
            throw new InvalidKeyTypeAlgorithmException('len is invalid');

        return $this->rsa_impl->encrypt($message);
    }

    /**
     * @param Key $key
     * @param string $enc_message
     * @return string
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function decrypt(Key $key, $enc_message){

        if(!($key instanceof RSAPrivateKey))
            throw new InvalidKeyTypeAlgorithmException('key is not private');

        if($key->getFormat() !== 'PKCS1')
            throw new InvalidKeyTypeAlgorithmException('keys is not on PKCS1 format');

        $res = $this->rsa_impl->loadKey($key->getEncoded());

        if(!$res)
            throw new InvalidKeyTypeAlgorithmException('could not parse the key');

        if($this->rsa_impl->getSize() < $this->getMinKeyLen())
            throw new InvalidKeyTypeAlgorithmException('len is invalid');

        return $this->rsa_impl->decrypt($enc_message);
    }

    /**
     * @return int
     */
    abstract public function getEncryptionMode();

    /**
     * @return string
     */
    abstract public function getMGFHash();

}