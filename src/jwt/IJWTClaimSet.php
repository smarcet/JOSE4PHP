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

use utils\IJsonObject;
use utils\NumericDate;
use utils\StringOrURI;
use jwt\exceptions\ClaimAlreadyExistsException;
/**
 * Interface IJWTClaimSet
 * @package jwt
 *
 * https://tools.ietf.org/html/rfc7519#section-4
 * The JWT Claims Set represents a JSON object whose members are the
 * claims conveyed by the JWT.  The Claim Names within a JWT Claims Set
 * MUST be unique; JWT parsers MUST either reject JWTs with duplicate
 * Claim Names or use a JSON parser that returns only the lexically last
 * duplicate member name, as specified in Section 15.12 ("The JSON
 * Object") of ECMAScript 5.1 [ECMAScript].
 * The set of claims that a JWT must contain to be considered valid is
 * context dependent and is outside the scope of this specification.
 * Specific applications of JWTs will require implementations to
 * understand and process some claims in particular ways.  However, in
 * the absence of such requirements, all claims that are not understood
 * by implementations MUST be ignored.
 */
interface IJWTClaimSet extends IJsonObject, \ArrayAccess {

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
     * @param JWTClaim $claim
     * @throws ClaimAlreadyExistsException
     */
    public function addCustomClaim(JWTClaim $claim);

    /**
     * @return JWTClaim[]
     */
    public function getClaims();
}