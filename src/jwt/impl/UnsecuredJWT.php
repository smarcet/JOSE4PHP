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
use jwt\IJWT;
use jwt\IJWTClaimSet;
use utils\json_types\StringOrURI;
/**
 * Class UnsecuredJWT
 * @package jwt\impl
 *
 * https://tools.ietf.org/html/rfc7519#section-6
 *
 *
 */
final class UnsecuredJWT extends JWT implements IJWTSnapshot
{

    const EmptySignature = '';

    /**
     * @param IJWTClaimSet $claim_set
     */
    protected function __construct(IJWTClaimSet $claim_set)
    {

        parent::__construct
        (
            new JOSEHeader
            (
                new StringOrURI('none'),
                new StringOrURI('JWT')
            ),
            $claim_set
        );

        $this->signature = self::EmptySignature;
    }

    /**
     * @return string
     */
    public function getRawPayload()
    {
       return '';
    }

    /**
     * @param IJWTClaimSet $claim_set
     * @return IJWT
     */
    static public function fromClaimSet(IJWTClaimSet $claim_set)
    {
        return new UnsecuredJWT($claim_set);
    }

    /**
     * @param string $compact_serialization
     * @return IJWT
     */
    public static function fromCompactSerialization($compact_serialization)
    {
        list($header, $payload, $signature) = JWTSerializer::deserialize($compact_serialization);

        if(!($payload instanceof IJWTClaimSet))
            throw new \RuntimeException('Invalid payload type!');

        $jwt = new UnsecuredJWT($payload);
        $jwt->header = $header;
        return $jwt;
    }
}