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

        if($private_key->hasPassword()){
            $this->rsa_impl->setPassword($private_key->getPassword());
        }

        $res = $this->rsa_impl->loadKey($private_key->getEncoded());

        if(!$res)
            throw new InvalidKeyTypeAlgorithmException;

        $this->rsa_impl->setHash($this->getHashingAlgorithm());
        $this->rsa_impl->setMGFHash($this->getHashingAlgorithm());
        $this->rsa_impl->setSignatureMode($this->getPaddingMode());
        return $this->rsa_impl->sign($message);
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

        $res = $this->rsa_impl->loadKey($key->getEncoded());

        if(!$res) throw new InvalidKeyTypeAlgorithmException;

        $this->rsa_impl->setHash($this->getHashingAlgorithm());
        $this->rsa_impl->setMGFHash($this->getHashingAlgorithm());
        $this->rsa_impl->setSignatureMode($this->getPaddingMode());

        return $this->rsa_impl->verify($message, $signature);
    }

    /**
     * @return int
     */
    abstract public function getPaddingMode();
}