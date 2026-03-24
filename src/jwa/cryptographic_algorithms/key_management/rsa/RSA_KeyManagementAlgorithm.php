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
use phpseclib3\Crypt\PublicKeyLoader;
use security\Key;
use security\rsa\CustomAsymmetricKey;
use security\rsa\RSAPrivateKey;
use security\rsa\RSAPublicKey;
/**
 * Class RSA_KeyManagementAlgorithm
 * @package jwa\cryptographic_algorithms\key_management\rsa
 */
abstract class RSA_KeyManagementAlgorithm
    extends Abstract_RSA_Algorithm
    implements EncryptionAlgorithm, KeyEncryption {

    // Constructor removed - encryption configuration now done per-operation in encrypt()/decrypt()

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

        try {
            $raw_key = PublicKeyLoader::load($key->getEncoded());
            $loaded_key = new CustomAsymmetricKey($raw_key);
        } catch (\Exception $e) {
            throw new InvalidKeyTypeAlgorithmException('could not parse the key', 0, $e);
        }

        if($loaded_key->getModulus()->getLength() < $this->getMinKeyLen())
            throw new InvalidKeyTypeAlgorithmException('len is invalid');

        $configured_key = $raw_key->withPadding($this->getEncryptionMode())
                                   ->withHash($this->getHashingAlgorithm())
                                   ->withMGFHash($this->getMGFHash());

        return $configured_key->encrypt($message);
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

        try {
            $raw_key = PublicKeyLoader::load($key->getEncoded());
            $loaded_key = new CustomAsymmetricKey($raw_key);
        } catch (\Exception $e) {
            throw new InvalidKeyTypeAlgorithmException('could not parse the key', 0, $e);
        }

        if($loaded_key->getModulus()->getLength() < $this->getMinKeyLen())
            throw new InvalidKeyTypeAlgorithmException('len is invalid');

        $configured_key = $raw_key->withPadding($this->getEncryptionMode())
                                   ->withHash($this->getHashingAlgorithm())
                                   ->withMGFHash($this->getMGFHash());

        return $configured_key->decrypt($enc_message);
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