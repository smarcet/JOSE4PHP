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

use jwt\exceptions\ClaimAlreadyExistsException;
use jwt\IJWTClaimSet;
use jwt\JWTClaim;
use jwt\RegisteredJWTClaimNames;
use utils\JsonObject;
use utils\JsonValue;
use utils\NumericDate;
use utils\StringOrURI;

/**
 * Class JWTClaimSet
 * @package jwt\impl
 */
final class JWTClaimSet
    extends JsonObject
    implements IJWTClaimSet {

    /**
     * @param StringOrURI $issuer
     * @param StringOrURI $subject
     * @param StringOrURI $audience
     * @param NumericDate $issued_at
     * @param NumericDate $expiration_time
     * @param JsonValue   $id
     * @param NumericDate $nbf
     */
    public function __construct(StringOrURI $issuer          = null,
                                StringOrURI $subject         = null,
                                StringOrURI $audience        = null,
                                NumericDate $issued_at       = null,
                                NumericDate $expiration_time = null,
                                JsonValue   $id              = null,
                                NumericDate $nbf             = null){

        $this->set[RegisteredJWTClaimNames::Issuer]         = $issuer;
        $this->set[RegisteredJWTClaimNames::Subject]        = $subject;
        $this->set[RegisteredJWTClaimNames::Audience]       = $audience;
        $this->set[RegisteredJWTClaimNames::IssuedAt]       = $issued_at;
        $this->set[RegisteredJWTClaimNames::ExpirationTime] = $expiration_time;
        $this->set[RegisteredJWTClaimNames::JWTID]          = $id;
        $this->set[RegisteredJWTClaimNames::NotBefore]      = $nbf;
    }

       /**
     * @return StringOrURI
     */
    public function getIssuer()
    {
        return $this[RegisteredJWTClaimNames::Issuer];
    }

    /**
     * @return StringOrURI
     */
    public function getSubject()
    {
        return $this[RegisteredJWTClaimNames::Subject];
    }

    /**
     * @return StringOrURI
     */
    public function getAudience()
    {
        return $this[RegisteredJWTClaimNames::Audience];
    }

    /**
     * @return NumericDate
     */
    public function getExpirationTime()
    {
        return $this[RegisteredJWTClaimNames::ExpirationTime];
    }

    /**
     * @return NumericDate
     */
    public function getNotBefore()
    {
        return $this[RegisteredJWTClaimNames::NotBefore];
    }

    /**
     * @return NumericDate
     */
    public function getIssuedAt()
    {
        return $this[RegisteredJWTClaimNames::IssuedAt];
    }

    /**
     * @return JsonValue
     */
    public function getJWTID()
    {
        return $this[RegisteredJWTClaimNames::JWTID];
    }

    /**
     * @param JWTClaim $claim
     * @throws ClaimAlreadyExistsException
     */
    public function addClaim(JWTClaim $claim)
    {
        if(isset($this->set[$claim->getName()]))
            throw new ClaimAlreadyExistsException($claim->getName());

        $this->set[$claim->getName()] = $claim->getValue();
    }

    /**
     * @return JWTClaim[]
     */
    public function getClaims()
    {
        // TODO: Implement getClaims() method.
    }

    /**
     * @param string $issuer
     * @return void
     */
    public function setIssuer($issuer)
    {
        // TODO: Implement setIssuer() method.
    }

    /**
     * @param string $audience
     * @return void
     */
    public function setAudience($audience)
    {
        // TODO: Implement setAudience() method.
    }

    /**
     * @param string $subject
     * @return void
     */
    public function setSubject($subject)
    {
        // TODO: Implement setSubject() method.
    }

    /**
     * @param int $minutes
     * @return void
     */
    public function setExpirationTimeMinutesInTheFuture($minutes)
    {
        // TODO: Implement setExpirationTimeMinutesInTheFuture() method.
    }

    /**
     * @return void
     */
    public function setGeneratedJwtId()
    {
        // TODO: Implement setGeneratedJwtId() method.
    }

    /**
     * @return void
     */
    public function setIssuedAtToNow()
    {
        // TODO: Implement setIssuedAtToNow() method.
    }

    /**
     * @param int $minutes
     * @return void
     */
    public function setNotBeforeMinutesInThePast($minutes)
    {
        // TODO: Implement setNotBeforeMinutesInThePast() method.
    }
}