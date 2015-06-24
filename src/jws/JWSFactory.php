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

namespace jws;

use jwk\exceptions\InvalidJWKType;
use jwk\IJWK;
use jwk\JSONWebKeyPublicKeyUseValues;
use jws\exceptions\JWSInvalidPayloadException;
use jws\impl\JWS;
use jwt\IJWTClaimSet;
use jwt\impl\JOSEHeader;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;
use utils\json_types\StringOrURI;

/**
 * Class JWSFactory
 * @package jws
 */
final class JWSFactory {

    /**
     * @param IJWK $key
     * @param StringOrURI $alg
     * @param IJWSPayloadSpec $payload
     * @param string $signature
     * @return JWS
     * @throws InvalidJWKType
     * @throws JWSInvalidPayloadException
     */
    static public function build(IJWK $key, StringOrURI $alg, IJWSPayloadSpec $payload, $signature = ''){

        if(is_null($key))
            throw new InvalidJWKType();

        if(is_null($payload))
            throw new JWSInvalidPayloadException('missing payload');

        if($key->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Signature)
            throw new InvalidJWKType(sprintf('use % not supported (sig)',$key->getKeyUse()->getString()));

        $header = new JOSEHeader($alg);

        $jws = JWS::fromHeaderClaimsAndSignature($header, $payload, $signature);

        $jws->setKey($key);

        return $jws;
    }
}