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

namespace jws\impl;

use jwk\IAsymetricJWK;
use jwk\IJWK;
use jws\exceptions\JWSInvalidJWKException;
use jws\exceptions\JWSInvalidPayloadException;
use jws\exceptions\JWSNotSupportedAlgorithm;
use jws\IJWS;
use jws\JWSupportedSigningAlgorithms;
use jws\signing_algorithms\JWSAlgorithmRegistry;
use jwt\IJOSEHeader;
use jwt\IJWT;
use jwt\IJWTClaimSet;
use jwt\impl\JWT;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;
use jwt\utils\JOSEHeaderAssembler;
use jwt\utils\JWTClaimSetAssembler;
use jwt\utils\JWTRawAssembler;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;

/**
 * Class JWS
 * @package jws\impl
 */
final class JWS
    extends JWT
    implements IJWS {

    /**
     * @var IJWK
     */
    private $jwk = null;

    /**
     * @var string
     */
    private $payload = null;

    /**
     * @param IJOSEHeader $header
     * @param IJWTClaimSet $claim_set
     * @param string $signature
     * @throws JWSNotSupportedAlgorithm
     */
    protected function __construct(IJOSEHeader $header, IJWTClaimSet $claim_set = null, $signature = ''){

        if(!is_null($claim_set))
            $header->addHeader(new JOSEHeaderParam(RegisteredJOSEHeaderNames::Type, new StringOrURI('JWT')));

        parent::__construct($header, $claim_set);
        if(!in_array($this->getSigningAlgorithm()->getString() , JWSupportedSigningAlgorithms::$algorithms))
            throw new JWSNotSupportedAlgorithm(sprintf('algo %s', $this->getSigningAlgorithm()->getString()));

        $this->signature = $signature;
    }

    /**
     * @param string $payload
     * @return IJWS
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @return string
     */
    public function serialize()
    {
        if(!is_null($this->jwk->getId()))
            $this->header->addHeader(new JOSEHeaderParam(RegisteredJOSEHeaderNames::KeyID, $this->jwk->getId()));
        $this->sign();
        return parent::serialize();
    }

    /**
     * @return $this
     * @throws JWSInvalidJWKException
     * @throws JWSInvalidPayloadException
     * @throws JWSNotSupportedAlgorithm
     */
    public function sign()
    {

        if(is_null($this->jwk))
            throw new JWSInvalidJWKException;

        $alg                 = JWSAlgorithmRegistry::getInstance()->getAlgorithm($this->header->getAlgorithm()->getString());
        $secured_input_bytes = JOSEHeaderAssembler::serialize($this->header) . '.' .$this->getEncodedPayload();

        $this->signature = $alg->sign($this->jwk->getKey(), $secured_input_bytes);

        return $this;
    }

    public function getEncodedPayload(){
        $enc_payload = '';
        if($this->claim_set){
            $enc_payload = JWTClaimSetAssembler::serialize($this->claim_set);
        }
        else if(!empty($this->payload)){
            $enc_payload = JWTRawAssembler::serialize($this->payload);
        }
        else{
            throw new JWSInvalidPayloadException('payload not set!');
        }
        return $enc_payload;
    }



    /**
     * @param IJWK $key
     * @return $this
     */
    public function setKey(IJWK $key)
    {
        $this->jwk = $key;
        return $this;
    }

    /**
     * @param string $compact_serialization
     * @return $this
     */
    static public function fromCompactSerialization($compact_serialization)
    {
        list($header, $payload, $signature) = parent::unSerialize($compact_serialization);
        $claim_set = ($header->getType()->getString() === 'JWT') ? $payload : null;
        return new JWS($header, $claim_set, $signature);
    }

    /**
     * @return StringOrURI
     */
    public function getSigningAlgorithm()
    {
        return $this->header->getAlgorithm();
    }

    /**
     * @return StringOrURI
     */
    public function getType()
    {
        return $this->header->getType();
    }

    /**
     * @param string $original_alg
     * @return bool
     * @throws JWSInvalidJWKException
     * @throws JWSInvalidPayloadException
     * @throws JWSNotSupportedAlgorithm
     */
    public function verify($original_alg)
    {
        if(is_null($this->jwk))
            throw new JWSInvalidJWKException;

        if(!is_null($this->jwk->getId()) && !is_null($this->header->getKeyID()) && $this->header->getKeyID()->getValue() != $this->jwk->getId()->getValue())
            throw new JWSInvalidJWKException(sprintf('original kid %s - current kid %s', $this->header->getKeyID()->getValue() , $this->jwk->getId()->getValue()));

        if(!in_array($original_alg, JWSupportedSigningAlgorithms::$algorithms))
            throw new JWSNotSupportedAlgorithm(sprintf('algo %s', $original_alg));

        $former_alg = $this->header->getAlgorithm()->getString();
        if($former_alg != $original_alg)
            throw new JWSNotSupportedAlgorithm(sprintf('former alg %s - original alg %s', $former_alg, $original_alg));
        $alg = JWSAlgorithmRegistry::getInstance()->getAlgorithm($former_alg);
        $secured_input_bytes = JOSEHeaderAssembler::serialize($this->header) . '.' .$this->getEncodedPayload();
        $key = ($this->jwk instanceof IAsymetricJWK) ? $this->jwk->getPublicKey() : $this->jwk->getKey();
        return $alg->verify($key, $this->signature, $secured_input_bytes);

    }

    /**
     * @return string
     */
    public function getRawPayload()
    {
        return $this->payload;
    }

    /**
     * @param IJWTClaimSet $claim_set
     * @throws \Exception
     */
    static public function fromClaimSet(IJWTClaimSet $claim_set)
    {
        throw new \Exception;
    }

    static public function fromHeaderClaimsAndSignature(IJOSEHeader $header, IJWTClaimSet $claim_set = null, $signature = ''){
        return new JWS($header, $claim_set,$signature );
    }
}