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
use jwt\exceptions\ClaimAlreadyExistsException;
use jwt\IJWTClaimSet;
use jwt\IJWTIdGenerator;
use jwt\JWTClaim;
use jwt\RegisteredJWTClaimNames;
use utils\JsonObject;
use utils\json_types\JsonValue;
use utils\json_types\NumericDate;
use utils\json_types\StringOrURI;
/**
 * Class JWTClaimSet
 * @package jwt\impl
 */
final class JWTClaimSet extends JsonObject implements IJWTClaimSet
{

    /**
     * @param StringOrURI $issuer
     * @param StringOrURI $subject
     * @param StringOrURI $audience
     * @param NumericDate $issued_at
     * @param NumericDate $expiration_time
     * @param JsonValue $id
     * @param NumericDate $nbf
     */
    public function __construct
    (
        StringOrURI $issuer          = null,
        StringOrURI $subject         = null,
        StringOrURI $audience        = null,
        NumericDate $issued_at       = null,
        NumericDate $expiration_time = null,
        JsonValue   $id              = null,
        NumericDate $nbf             = null
    )
    {

        $this->set[RegisteredJWTClaimNames::Issuer] = $issuer;
        $this->set[RegisteredJWTClaimNames::Subject] = $subject;
        $this->set[RegisteredJWTClaimNames::Audience] = $audience;
        $this->set[RegisteredJWTClaimNames::IssuedAt] = $issued_at;
        $this->set[RegisteredJWTClaimNames::ExpirationTime] = $expiration_time;
        $this->set[RegisteredJWTClaimNames::JWTID] = $id;
        $this->set[RegisteredJWTClaimNames::NotBefore] = $nbf;
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
        if (isset($this->set[$claim->getName()]))
            throw new ClaimAlreadyExistsException($claim->getName());

        $this->set[$claim->getName()] = $claim->getValue();
    }

    /**
     * @return JWTClaim[]
     */
    public function getClaims()
    {
       $claims = array();
       foreach($this->set as $k => $v)
       {
           array_push($claims, new JWTClaim($k, $v));
       }
       return $claims;
    }

    /**
     * @param StringOrURI $issuer
     * @return void
     */
    public function setIssuer($issuer)
    {
        $this->set[RegisteredJWTClaimNames::Issuer] = $issuer;
    }

    /**
     * @param StringOrURI $audience
     * @return void
     */
    public function setAudience($audience)
    {
        $this->set[RegisteredJWTClaimNames::Audience] = $audience;
    }

    /**
     * @param StringOrURI $subject
     * @return void
     */
    public function setSubject($subject)
    {
        $this->set[RegisteredJWTClaimNames::Subject] = $subject;
    }

    /**
     * @param int $minutes
     * @return void
     */
    public function setExpirationTimeMinutesInTheFuture($minutes)
    {
        $this->setExpirationTime($this->offsetFromNow($minutes));
    }

    /**
     * @param IJWTIdGenerator $generator
     * @return void
     */
    public function setGeneratedJwtId(IJWTIdGenerator $generator)
    {
        $generator->generateUniqueId($this);
    }

    /**
     * @return void
     */
    public function setIssuedAtToNow()
    {
        $this->setIssued(NumericDate::now());
    }

    /**
     * @param int $minutes
     * @return void
     */
    public function setNotBeforeMinutesInThePast($minutes)
    {
        $this->setNotBefore($this->offsetFromNow(-1 * $minutes));
    }

    /**
     * @param int $offset_minutes
     * @return NumericDate
     */
    private function offsetFromNow($offset_minutes)
    {
        $numeric_date = NumericDate::now();
        $seconds = $offset_minutes * 60;
        $numeric_date->addSeconds($seconds);
        return $numeric_date;
    }

    /**
     * @param NumericDate $expiration_time
     * @return void
     */
    public function setExpirationTime(NumericDate $expiration_time)
    {

        $this->set[RegisteredJWTClaimNames::ExpirationTime] = $expiration_time;
    }

    /**
     * @param NumericDate $not_before
     * @return void
     */
    public function setNotBefore(NumericDate $not_before)
    {
        $this->set[RegisteredJWTClaimNames::NotBefore] = $not_before;
    }

    /**
     * @param NumericDate $issued
     * @return void
     */
    public function setIssued(NumericDate $issued)
    {
        $this->set[RegisteredJWTClaimNames::IssuedAt] = $issued;
    }

    /**
     * @param JsonValue $jwt_id
     * @return void
     */
    public function setJwtId(JsonValue $jwt_id)
    {
        $this->set[RegisteredJWTClaimNames::JWTID] = $jwt_id;
    }

    /**
     * @param string $claim_name
     * @return JWTClaim|null
     */
    public function getClaimByName($claim_name)
    {
       return isset($this->set[$claim_name]) ?
           $this->set[$claim_name] :
           null;
    }
}