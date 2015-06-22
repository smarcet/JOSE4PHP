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

namespace jwt\impl;

use jwt\exceptions\InvalidJWTException;
use jwt\IJOSEHeader;
use jwt\IJWT;
use jwt\IJWTClaimSet;
use jwt\utils\JOSEHeaderAssembler;
use jwt\utils\JWTClaimSetAssembler;
use jwt\utils\JWTRawAssembler;

/**
 * Class JWT
 * @package jwt\impl
 */
abstract class JWT
    implements IJWT {

    /**
     * @var IJOSEHeader
     */
    protected $header;

    /**
     * @var IJWTClaimSet
     */
    protected $claim_set;

    /**
     * @var string
     */
    protected $signature;


    /**
     * @param IJOSEHeader $header
     * @param IJWTClaimSet $claim_set
     */
    protected function __construct(IJOSEHeader $header, IJWTClaimSet $claim_set){

        $this->header    = $header;
        $this->claim_set = $claim_set;
    }

    /**
     * @return IJOSEHeader
     */
    public function getJOSEHeader()
    {
        return $this->header;
    }

    /**
     * @return IJWTClaimSet
     */
    public function getClaimSet()
    {
       return  $this->claim_set;
    }

    /**
     * @return string|null
     */
    public function getSignature()
    {
       return $this->signature;
    }

    /**
     * @return string
     */
    public function serialize()
    {
        $header    = JOSEHeaderAssembler::serialize($this->header);
        $claim_set = ($this->header->getType()->getString() === 'JWT' && !is_null($this->claim_set)) ? JWTClaimSetAssembler::serialize($this->claim_set) : JWTRawAssembler::serialize($this->getRawPayload());
        $signature = JWTRawAssembler::serialize($this->signature);
        return sprintf('%s.%s.%s', $header, $claim_set, $signature);
    }

    /**
     * @param string $input
     * @return array
     * @throws InvalidJWTException
     */
    public static function unSerialize($input)
    {
        $e_parts = explode('.',$input);
        if(count($e_parts) < 2)
            throw new InvalidJWTException(sprintf('%s has only 2 or less encoded parts!'));

        $e_header    = $e_parts[0];
        $e_payload   = $e_parts[1];
        $e_signature = count($e_parts)>2 ? $e_parts[2] : '';

        $header    = JOSEHeaderAssembler::unSerialize($e_header);
        $payload   = ($header->getType()->getString() === 'JWT') ? JWTClaimSetAssembler::unSerialize($e_payload) : JWTRawAssembler::unSerialize($e_payload);
        $signature = !empty($e_signature) ? JWTRawAssembler::unSerialize($e_signature): '';

        return array($header, $payload, $signature);
    }

}