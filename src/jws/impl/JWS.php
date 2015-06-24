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

use jwa\cryptographic_algorithms\digital_signatures\DigitalSignatureAlgorithm;
use jwa\cryptographic_algorithms\DigitalSignatures_MACs_Registry;
use jwa\cryptographic_algorithms\macs\MAC_Algorithm;
use jwk\IJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jwk\JSONWebKeyPublicKeyUseValues;
use jws\exceptions\JWSInvalidJWKException;
use jws\exceptions\JWSInvalidPayloadException;
use jws\exceptions\JWSNotSupportedAlgorithm;
use jws\IJWS;
use jws\IJWSPayloadClaimSetSpec;
use jws\IJWSPayloadSpec;
use jws\payloads\JWSPayloadFactory;
use jwt\IJOSEHeader;
use jwt\impl\JWT;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;
use jwt\utils\JOSEHeaderAssembler;
use jwt\utils\JWTClaimSetAssembler;
use jwt\utils\JWTRawAssembler;
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
     * @var IJWSPayloadSpec
     */
    private $payload = null;

    /**
     * @param IJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     * @param string $signature
     * @throws JWSNotSupportedAlgorithm
     */
    protected function __construct(IJOSEHeader $header, IJWSPayloadSpec $payload = null, $signature = ''){

        $claim_set = null;

        if(!is_null($payload) && $payload->isClaimSet() && $payload instanceof IJWSPayloadClaimSetSpec) {
            $header->addHeader(new JOSEHeaderParam(RegisteredJOSEHeaderNames::Type, new StringOrURI('JWT')));
            $claim_set = $payload->getClaimSet();
        }

        parent::__construct($header, $claim_set);

        $this->setPayload($payload);

        $this->signature = $signature;
    }

    /**
     * @param IJWSPayloadSpec $payload
     * @return IJWS
     */
    public function setPayload(IJWSPayloadSpec $payload)
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

    protected function serializePayload(){
        $e_payload = parent::serializePayload();
        if(empty($e_payload)){
            $e_payload = JWTRawAssembler::serialize($this->payload->getRaw());
        }
        return $e_payload;
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

        if($this->jwk->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Signature)
            throw new JWSInvalidJWKException(sprintf('use %s not supported.', $this->jwk->getKeyUse()->getString()));

        $alg    = DigitalSignatures_MACs_Registry::getInstance()->get($this->header->getAlgorithm()->getString());

        if(is_null($alg)) throw new JWSNotSupportedAlgorithm(sprintf('alg %s.',$this->header->getAlgorithm()->getString()));

        $secured_input_bytes = JOSEHeaderAssembler::serialize($this->header) . '.' .$this->getEncodedPayload();

        $key  = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::ComputeDigitalSignatureOrMAC);

        if($alg instanceof DigitalSignatureAlgorithm) {
            $this->signature = $alg->sign($key, $secured_input_bytes);
        }
        else if($alg instanceof MAC_Algorithm ) {
            $this->signature = $alg->digest($key, $secured_input_bytes);
        }
        else{
            throw new JWSNotSupportedAlgorithm(sprintf('alg %s.',$this->header->getAlgorithm()->getString()));
        }

        return $this;
    }

    /**
     * @return string
     * @throws JWSInvalidPayloadException
     */
    public function getEncodedPayload(){
        if(is_null($this->payload))
            throw new JWSInvalidPayloadException('payload is not set!');
        $enc_payload = '';
        if($this->payload->isClaimSet() && $this->payload instanceof IJWSPayloadClaimSetSpec){
            $enc_payload = JWTClaimSetAssembler::serialize($this->payload->getClaimSet());
        }
        else{
            $enc_payload = JWTRawAssembler::serialize($this->payload->getRaw());
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
        return new JWS($header, JWSPayloadFactory::build($payload), $signature);
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

        if($this->jwk->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Signature)
            throw new JWSInvalidJWKException(sprintf('use %s not supported ', $this->jwk->getKeyUse()->getString()));

        if(!is_null($this->jwk->getId()) && !is_null($this->header->getKeyID()) && $this->header->getKeyID()->getValue() != $this->jwk->getId()->getValue())
            throw new JWSInvalidJWKException(sprintf('original kid %s - current kid %s', $this->header->getKeyID()->getValue() , $this->jwk->getId()->getValue()));

        $alg = DigitalSignatures_MACs_Registry::getInstance()->get($original_alg);

        if(is_null($alg))
            throw new JWSNotSupportedAlgorithm(sprintf('algo %s', $original_alg));

        $former_alg = $this->header->getAlgorithm()->getString();

        if($former_alg != $original_alg)
            throw new JWSNotSupportedAlgorithm(sprintf('former alg %s - original alg %s', $former_alg, $original_alg));

        $secured_input_bytes = JOSEHeaderAssembler::serialize($this->header) . '.' .$this->getEncodedPayload();

        // use public key / secret
        $key = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::VerifyDigitalSignatureOrMAC);
        return $alg->verify($key, $secured_input_bytes, $this->signature);
    }

    /**
     * @return IJWSPayloadSpec
     */
    public function getPayload()
    {
        return $this->payload;
    }

     /**
     * @param IJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     * @param string $signature
     * @return IJWS
     */
    static public function fromHeaderClaimsAndSignature(IJOSEHeader $header, IJWSPayloadSpec $payload = null , $signature = ''){
        return new JWS($header, $payload, $signature );
    }
}