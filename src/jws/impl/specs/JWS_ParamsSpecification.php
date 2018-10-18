<?php namespace jws\impl\specs;
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
use jwk\exceptions\InvalidJWKType;
use jwk\IJWK;
use jws\exceptions\JWSInvalidPayloadException;
use jws\IJWS_ParamsSpecification;
use jws\IJWSPayloadSpec;
use jws\payloads\JWSPayloadFactory;
use utils\json_types\StringOrURI;
/**
 * Class JWS_ParamsSpecification
 * @package jws\impl\specs
 */
final class JWS_ParamsSpecification
    implements IJWS_ParamsSpecification {

    /**
     * @var IJWK
     */
    private $key;
    /**
     * @var StringOrURI
     */
    private $alg;
    /**
     * @var IJWSPayloadSpec
     */
    private $payload;
    /**
     * @var string
     */
    private $signature;

    /**
     * @param IJWK $key
     * @param StringOrURI $alg
     * @param mixed $payload
     * @param string $signature
     * @throws InvalidJWKType
     * @throws JWSInvalidPayloadException
     */
    public function __construct(IJWK $key, StringOrURI $alg, $payload, $signature = ''){

        if(is_null($key))
            throw new InvalidJWKType();

        if(is_null($payload))
            throw new JWSInvalidPayloadException('missing payload');

        $this->key = $key;
        $this->alg = $alg;
        $this->payload = JWSPayloadFactory::build($payload);
        $this->signature = $signature;
    }


    /**
     * @return IJWK
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return StringOrURI
     */
    public function getAlg()
    {
       return $this->alg;
    }

    /**
     * @return IJWSPayloadSpec
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @return null|string
     */
    public function getSignature()
    {
        return $this->signature;
    }
}