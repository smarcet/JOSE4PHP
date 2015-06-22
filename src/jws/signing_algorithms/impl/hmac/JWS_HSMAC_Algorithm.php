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

namespace jws\signing_algorithms\impl\hmac;


use jwk\utils\Key;
use jws\signing_algorithms\exceptions\IJWSInvalidKeyLenAlgorithm;
use jws\signing_algorithms\IJWSAlgorithm;

/**
 * Class JWS_HSMAC_Algorithm
 * @package jws\signing_algorithms\impl
 */
abstract class JWS_HSMAC_Algorithm implements IJWSAlgorithm {

    /**
     * @param Key $key
     * @param string $secured_input_bytes
     * @return string
     * @throws IJWSInvalidKeyLenAlgorithm
     */
    public function sign(Key $key, $secured_input_bytes)
    {
        if($this->getMinKeyLen() > $key->getBitLength())
            throw new IJWSInvalidKeyLenAlgorithm(sprintf('min len %s - cur len %s.',$this->getMinKeyLen(), $key->getBitLength()));

        return hash_hmac($this->getAlgo(), $secured_input_bytes, $key->getEncoded(), true);
    }

    /**
     * @return string
     */
    abstract protected function getAlgo();

    /**
     * @return int
     */
    abstract protected function getMinKeyLen();

    /**
     * @param Key $key
     * @param string $current_sig
     * @param string $secured_input_bytes
     * @return bool
     * @throws IJWSInvalidKeyLenAlgorithm
     */
    public function verify(Key $key, $current_sig, $secured_input_bytes)
    {
       return $current_sig === $this->sign($key,$secured_input_bytes);
    }
}