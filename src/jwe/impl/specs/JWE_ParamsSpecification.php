<?php namespace jwe\impl\specs;
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
use jwe\exceptions\JWEInvalidPayloadException;
use jwe\exceptions\JWEInvalidRecipientKeyException;
use jwe\IJWE_ParamsSpecification;
use jwk\IJWK;
use jws\IJWSPayloadSpec;
use jws\payloads\JWSPayloadFactory;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;
/**
 * Class JWE_ParamsSpecification
 * @package jwe\impl\specs
 */
final class JWE_ParamsSpecification
    implements IJWE_ParamsSpecification {

    /**
     * @var IJWK
     */
    private $key;
    /**
     * @var StringOrURI
     */
    private $alg;

    /**
     * @var StringOrURI
     */
    private $enc;
    /**
     * @var IJWSPayloadSpec
     */
    private $payload;

    /**
     * @var JsonValue
     */
    private $zip;


    /**
     * @param IJWK $key
     * @param StringOrURI $alg
     * @param StringOrURI $enc
     * @param $payload
     * @param JsonValue $zip
     * @throws JWEInvalidPayloadException
     * @throws JWEInvalidRecipientKeyException
     */
    public function __construct(IJWK $key, StringOrURI $alg, StringOrURI $enc, $payload,  JsonValue $zip = null)
    {

        if(is_null($key))
            throw new JWEInvalidRecipientKeyException();

        if(is_null($payload))
            throw new JWEInvalidPayloadException('missing payload');

        $this->key     = $key;
        $this->alg     = $alg;
        $this->enc     = $enc;
        $this->zip     = $zip;

        $this->payload = JWSPayloadFactory::build($payload);
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
     * @return IJWK
     */
    public function getRecipientKey()
    {
        return $this->key;
    }

    /**
     * @return StringOrURI
     */
    public function getEnc()
    {
        return $this->enc;
    }

    /**
     * @return JsonValue
     */
    public function getZip()
    {
        return $this->zip;
    }
}