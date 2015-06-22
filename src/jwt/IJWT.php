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

namespace jwt;
use jwt\exceptions\InvalidJWTException;

/**
 * Interface IJWT
 * @package jwt
 */
interface IJWT {

    /**
     * @return IJOSEHeader
     */
    public function getJOSEHeader();

    /**
     * @return IJWTClaimSet
     */
    public function getClaimSet();

    /**
     * @return string|null
     */
    public function getSignature();

    /**
     * @return string
     */
    public function serialize();

    /**
     * @param string $input
     * @return array
     * @throws InvalidJWTException
     */
    public static function unSerialize($input);

    /**
     * @return string
     */
    public function getRawPayload();

    /**
     * @param IJWTClaimSet $claim_set
     * @return IJWT
     */
    static  public function fromClaimSet(IJWTClaimSet $claim_set);
}