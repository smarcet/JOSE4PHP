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

namespace jws\signing_algorithms\impl\rsa;

use jwk\utils\Key;
use jws\signing_algorithms\exceptions\IJWSInvalidKeyLenAlgorithm;
use jws\signing_algorithms\IJWSAlgorithm;

/**
 * Class JWS_RSA_Algorithm
 * @package jws\signing_algorithms\impl
 */
abstract class JWS_RSA_Algorithm
    implements IJWSAlgorithm {


    /**
     * @var \Crypt_RSA
     */
    protected $rsa_impl;

    public function __construct(){
        $this->rsa_impl = new \Crypt_RSA();
    }

    /**
     * @param Key $key
     * @param string $secured_input_bytes
     * @return string
     * @throws IJWSInvalidKeyLenAlgorithm
     */
    public function sign(Key $key, $secured_input_bytes)
    {
        if($this->getMinKeyLen() > $key->getBitLength())
            throw new IJWSInvalidKeyLenAlgorithm(sprintf('min len %s - cur len %s.',$this->minimum_key_length, $key->getBitLength()));

        $this->rsa_impl->loadKey($key->getEncoded());

        $this->rsa_impl->setHash($this->getAlgo());
        $this->rsa_impl->setMGFHash($this->getAlgo());
        $this->rsa_impl->setSignatureMode($this->getPaddingMode());
        return $this->rsa_impl->sign($secured_input_bytes);
    }

    /**
     * @return int
     */
    abstract protected function getMinKeyLen();

    /**
     * @return string
     */
    abstract protected function getAlgo();

    /**
     * @return int
     */
    abstract protected function getPaddingMode();


    /**
     * @param Key $key
     * @param string $current_sig
     * @param string $secured_input_bytes
     * @return bool
     * @throws IJWSInvalidKeyLenAlgorithm
     */
    public function verify(Key $key, $current_sig, $secured_input_bytes)
    {
        if($this->getMinKeyLen() > $key->getBitLength())
            throw new IJWSInvalidKeyLenAlgorithm(sprintf('min len %s - cur len %s.',$this->minimum_key_length, $key->getBitLength()));

        $this->rsa_impl->loadKey($key->getEncoded());

        $this->rsa_impl->setHash($this->getAlgo());
        $this->rsa_impl->setMGFHash($this->getAlgo());
        $this->rsa_impl->setSignatureMode($this->getPaddingMode());

        return $this->rsa_impl->verify($secured_input_bytes, $current_sig);
    }
}