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
use utils\json_types\JsonValue;
use utils\json_types\NumericDate;
use utils\json_types\StringOrURI;
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
interface IJWTClaimSet extends IReadOnlyJWTClaimSet {

    /**
     * @param StringOrURI $issuer
     * @return void
     */
    public function setIssuer($issuer);

    /**
     * @param StringOrURI $audience
     * @return void
     */
    public function setAudience($audience);

    /**
     * @param StringOrURI $subject
     * @return void
     */
    public function setSubject($subject);

    /**
     * @param int $minutes
     * @return void
     */
    public function setExpirationTimeMinutesInTheFuture($minutes);

    /**
     * @param IJWTIdGenerator $generator
     * @return void
     */
    public function setGeneratedJwtId(IJWTIdGenerator $generator);

    /**
     * @return void
     */
    public function setIssuedAtToNow();

    /**
     * @param NumericDate $issued
     * @return void
     */
    public function setIssued(NumericDate $issued);

    /**
     * @param JsonValue $jwt_id
     * @return void
     */
    public function setJwtId(JsonValue $jwt_id);

    /**
     * @param int $minutes
     * @return void
     */
    public function setNotBeforeMinutesInThePast($minutes);

    /**
     * @param JWTClaim $claim
     * @throws ClaimAlreadyExistsException
     */
    public function addClaim(JWTClaim $claim);

    /**
     * @param NumericDate $expiration_time
     * @return void
     */
    public function setExpirationTime(NumericDate $expiration_time);

    /**
     * @param NumericDate $not_before
     * @return void
     */
    public function setNotBefore(NumericDate $not_before);

}