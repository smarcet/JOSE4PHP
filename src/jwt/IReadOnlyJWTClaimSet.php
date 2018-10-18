<?php namespace jwt;
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
use utils\json_types\IJsonObject;
use utils\json_types\NumericDate;
use utils\json_types\StringOrURI;
/**
 * Interface IReadOnlyJWTClaimSet
 * @package jwt
 */
interface IReadOnlyJWTClaimSet extends IJsonObject, \ArrayAccess {

    /**
     * @return StringOrURI
     */
    public function getIssuer();

    /**
     * @return StringOrURI
     */
    public function getSubject();

    /**
     * @return StringOrURI
     */
    public function getAudience();

    /**
     * @return NumericDate
     */
    public function getExpirationTime();

    /**
     * @return NumericDate
     */
    public function getNotBefore();
    
    /**
     * @return NumericDate
     */
    public function getIssuedAt();

    /**
     * @return string
     */
    public function getJWTID();
    
    /**
     * @return JWTClaim[]
     */
    public function getClaims();

    /**
     * @param string $claim_name
     * @return JWTClaim|null
     */
    public function getClaimByName($claim_name);
}