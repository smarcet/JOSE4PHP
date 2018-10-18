<?php namespace jwa\cryptographic_algorithms\macs;
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
use jwa\cryptographic_algorithms\exceptions\InvalidKeyLengthAlgorithmException;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyTypeAlgorithmException;
use jwa\cryptographic_algorithms\HashFunctionAlgorithm;
use jwk\JSONWebKeyTypes;
use security\SharedKey;
use security\Key;
/**
 * Class HSMAC_Algorithm
 * @package jwa\cryptographic_algorithms\macs
 *
 * https://tools.ietf.org/html/rfc2104
 */
abstract class HSMAC_Algorithm implements MAC_Algorithm, HashFunctionAlgorithm {

    /**
     * @param SharedKey $key
     * @param string $message
     * @return string
     * @throws InvalidKeyLengthAlgorithmException
     */
    public function digest(SharedKey $key, $message){

        if($this->getMinKeyLen() > $key->getBitLength())
            throw new InvalidKeyLengthAlgorithmException(sprintf('min len %s - cur len %s.',$this->getMinKeyLen(), $key->getBitLength()));

        return hash_hmac($this->getHashingAlgorithm(), $message, $key->getSecret(), true);
    }

    /**
     * @param Key $key
     * @param string $message
     * @param string $digest
     * @return bool
     * @throws InvalidKeyLengthAlgorithmException
     * @throws InvalidKeyTypeAlgorithmException
     */
    public function verify(Key $key, $message, $digest){
        if(!($key instanceof SharedKey)) throw new InvalidKeyTypeAlgorithmException;

        return $digest === $this->digest($key, $message);
    }

    /**
     * @return string
     */
    public function getKeyType()
    {
        return JSONWebKeyTypes::OctetSequence;
    }
}