<?php namespace jws\payloads;
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
use jws\IJWSPayloadClaimSetSpec;
use jws\IJWSPayloadRawSpec;
use jws\IJWSPayloadSpec;
use jwt\IJWTClaimSet;
/**
 * Class JWSPayloadFactory
 * @package jws\payloads
 */
final class JWSPayloadFactory {

    /**
     * @param mixed $content
     * @return IJWSPayloadSpec
     */
    public static function build($content){

        if($content instanceof IJWTClaimSet){
            return new _JWSPayloadClaimSetSpec($content);
        }
        else{
            return new _JWSPayloadRawSpec($content);
        }
    }
}

/**
 * Class _JWSPayloadClaimSetSpec
 * @package jws\payloads
 * @internal
 */
final class _JWSPayloadClaimSetSpec
    implements IJWSPayloadClaimSetSpec {

    /**
     * @var IJWTClaimSet
     */
    private $claim_set;

    /**
     * @param IJWTClaimSet $claim_set
     */
    public function __construct(IJWTClaimSet $claim_set){
        $this->claim_set = $claim_set;
    }

    /**
     * @return IJWTClaimSet
     */
    public function getClaimSet()
    {
        return $this->claim_set;
    }

    /**
     * @return bool
     */
    public function isRaw()
    {
        return false;
    }

    /**
     * @return bool
     */
    public function isClaimSet()
    {
        return true;
    }
}

/**
 * Class _JWSPayloadRawSpec
 * @package jws\payloads
 * @internal
 */
final class _JWSPayloadRawSpec
    implements IJWSPayloadRawSpec {

    /**
     * @var string
     */
    private $raw;

    /**
     * @param string $raw
     */
    public function __construct($raw){
        $this->raw = $raw;
    }

    /**
     * @return string
     */
    public function getRaw()
    {
       return $this->raw;
    }

    /**
     * @return bool
     */
    public function isRaw()
    {
       return true;
    }

    /**
     * @return bool
     */
    public function isClaimSet()
    {
        return false;
    }
}