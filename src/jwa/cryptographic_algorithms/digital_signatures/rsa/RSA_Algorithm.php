<?php namespace jwa\cryptographic_algorithms\digital_signatures\rsa;
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
use jwa\cryptographic_algorithms\digital_signatures\DigitalSignatureAlgorithm;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyLengthAlgorithmException;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyTypeAlgorithmException;
use jwa\cryptographic_algorithms\HashFunctionAlgorithm;
use phpseclib3\Crypt\PublicKeyLoader;
use security\Key;
use security\PrivateKey;
use security\rsa\RSAPrivateKey;
use security\rsa\RSAPublicKey;
/**
 * Class RSA_Algorithm
 * @package jwa\cryptographic_algorithms\digital_signatures\rsa
 */
abstract class RSA_Algorithm
    extends Abstract_RSA_Algorithm
    implements DigitalSignatureAlgorithm, HashFunctionAlgorithm
{


    /**
     * @param PrivateKey $private_key
     * @param string $message
     * @return string
     * @throws InvalidKeyLengthAlgorithmException
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function sign(PrivateKey $private_key, $message)
    {
        if(!($private_key instanceof RSAPrivateKey)) throw new InvalidKeyTypeAlgorithmException;

        if($this->getMinKeyLen() > $private_key->getBitLength())
            throw new InvalidKeyLengthAlgorithmException(sprintf('min len %s - cur len %s.',$this->getMinKeyLen(), $private_key->getBitLength()));

        $password = $private_key->hasPassword() ? $private_key->getPassword() : false;

        try {
            $key = PublicKeyLoader::load($private_key->getEncoded(), $password);
        } catch (\Throwable $e) {
            throw new InvalidKeyTypeAlgorithmException('could not load private key', 0, $e);
        }

        $key = $key->withHash($this->getHashingAlgorithm())
                   ->withMGFHash($this->getHashingAlgorithm())
                   ->withPadding($this->getPaddingMode());

        return $key->sign($message);
    }

    /**
     * @param Key $key
     * @param string $message
     * @param string $signature
     * @return bool
     * @throws InvalidKeyLengthAlgorithmException
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function verify(Key $key, $message, $signature)
    {
        if(!($key instanceof RSAPublicKey)) throw new InvalidKeyTypeAlgorithmException;

        if($this->getMinKeyLen() > $key->getBitLength())
            throw new InvalidKeyLengthAlgorithmException(sprintf('min len %s - cur len %s.',$this->getMinKeyLen(), $key->getBitLength()));

        try {
            $loaded_key = PublicKeyLoader::load($key->getEncoded());
        } catch (\Throwable $e) {
            throw new InvalidKeyTypeAlgorithmException('could not load public key', 0, $e);
        }

        $loaded_key = $loaded_key->withHash($this->getHashingAlgorithm())
                                 ->withMGFHash($this->getHashingAlgorithm())
                                 ->withPadding($this->getPaddingMode());

        return $loaded_key->verify($message, $signature);
    }

    /**
     * @return int
     */
    abstract public function getPaddingMode();
}