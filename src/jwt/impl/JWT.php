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

use jwt\IJOSEHeader;
use jwt\IJWT;
use jwt\IJWTClaimSet;


/**
 * Class JWT
 * @package jwt\impl
 */
abstract class JWT
    implements IJWT, IJWTSnapshot {

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
    protected function __construct(IJOSEHeader $header, IJWTClaimSet $claim_set = null){

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
        if($this)
        return JWTSerializer::serialize($this);
    }

    /**
     * @return array
     */
    public function take()
    {
        $payload = ($this->header->getType()->getString() === 'JWT') ?  $this->claim_set : '';
        return array(
            $this->header,
            $payload,
            $this->signature
          );
    }
}