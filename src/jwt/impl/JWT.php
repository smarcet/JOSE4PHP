<?php namespace jwt\impl;
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
use jwt\IJOSEHeader;
use jwt\IJWT;
use jwt\IJWTClaimSet;
/**
 * Class JWT
 * @package jwt\impl
 */
abstract class JWT implements IJWT, IJWTSnapshot
{

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
     * @param IJWTClaimSet|null $claim_set
     */
    protected function __construct(IJOSEHeader $header, IJWTClaimSet $claim_set = null)
    {

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
    public function toCompactSerialization()
    {
        return JWTSerializer::serialize($this);
    }

    /**
     * @return array
     */
    public function take()
    {
        $payload = ($this->header->getType()->getString() === 'JWT') ?  $this->claim_set : '';
        return array
        (
            $this->header,
            $payload,
            $this->signature
        );
    }

    /**
     * @param int $tolerance seconds of tolerance for iat
     * @return bool
     */
    public function isExpired($tolerance = 180)
    {
        $now = new \DateTime();
        $exp = $this->getClaimSet()->getExpirationTime()->getDateTime();
        if($exp < $now) return true;
        $iat = $this->getClaimSet()->getIssuedAt()->getDateTime();
        if($iat > $now) return true;
        $diff = $now->getTimestamp() - $iat->getTimestamp();
        return $diff > $tolerance;
    }
}