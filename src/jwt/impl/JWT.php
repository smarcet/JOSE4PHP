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

use jwe\IJWE;
use jwt\IJOSEHeader;
use jwt\IJWT;
use jwt\IJWTClaimSet;
use jwt\utils\JOSEHeaderSerializer;
use jwt\utils\JWTClaimSetAssembler;
use jws\IJWS;

/**
 * Class JWT
 * @package jwt\impl
 */
abstract class JWT
    implements IJWT, IJWS, IJWE {

    /**
     * @var IJOSEHeader
     */
    protected $header;

    /**
     * @var IJWTClaimSet
     */
    protected $claimSet;

    /**
     * @var string
     */
    protected $signature;


    /**
     * @param IJOSEHeader $header
     * @param IJWTClaimSet $claimSet
     */
    public function __construct(IJOSEHeader $header, IJWTClaimSet $claimSet){

        $this->header   = $header;
        $this->claimSet = $claimSet;
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
       return  $this->claimSet;
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
        $header    = JOSEHeaderSerializer::serialize($this->header);
        $claim_set = JWTClaimSetAssembler::serialize($this->claimSet);
        $signature = JWTSignatureAssembler::serialize($this->signature);
        return sprintf('%s.%s.%s', $header, $claim_set, $signature);
    }

    /**
     * @param string $input
     * @throws InvalidJWTException
     */
    public static function deserialize($input)
    {
        $e_parts = explode('.',$input);
        if(count($e_parts) < 2)
            throw new InvalidJWTException(sprintf('%s has only 2 or less encoded parts!'));

        $e_header    = $e_parts[0];
        $e_claim_set = $e_parts[1];
        $e_signature = count($e_parts)>2 ? $e_parts[2] : '';

    }

}