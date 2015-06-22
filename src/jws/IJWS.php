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

namespace jws;

use jwk\IJWK;
use jws\exceptions\JWSInvalidJWKException;
use jws\exceptions\JWSInvalidPayloadException;
use jws\exceptions\JWSNotSupportedAlgorithm;

/**
 * Interface IJWS
 * @package jws
 */
interface IJWS extends IJWSReadOnly {

    /**
     * @param string $payload
     * @return $this
     */
    public function setPayload($payload);

    /**
     * @return string
     */
    public function serialize();

    /**
     * @return $this
     * @throws JWSInvalidJWKException
     * @throws JWSInvalidPayloadException
     * @throws JWSNotSupportedAlgorithm
     */
    public function sign();

    /**
     * @param string $original_alg
     * @return bool
     * @throws JWSInvalidJWKException
     * @throws JWSInvalidPayloadException
     * @throws JWSNotSupportedAlgorithm
     */
    public function verify($original_alg);
    /**
     * @param IJWK $key
     * @return $this
     */
    public function setKey(IJWK $key);

    /**
     * @param string $compact_serialization
     * @return $this
     */
    static public function fromCompactSerialization($compact_serialization);

}