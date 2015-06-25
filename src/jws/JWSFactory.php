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
use jwk\JSONWebKeyPublicKeyUseValues;
use jws\impl\JWS;
use jwt\impl\JOSEHeader;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;

/**
 * Class JWSFactory
 * @package jws
 */
final class JWSFactory {

    /**
     * @param IJWS_Specification $spec
     * @return IJWS
     * @throws InvalidJWKType
     * @throws \RuntimeException
     */
    static public function build(IJWS_Specification $spec){

        if($spec instanceof IJWS_ParamsSpecification){
            if($spec->getKey()->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Signature)
                throw new InvalidJWKType(sprintf('use % not supported (sig)',$spec->getKey()->getKeyUse()->getString()));
            $header = new JOSEHeader($spec->getAlg());
            $jws = JWS::fromHeaderClaimsAndSignature($header, $spec->getPayload(), $spec->getSignature());
            $jws->setKey($spec->getKey());
            return $jws;
        }
        if($spec instanceof IJWS_CompactFormatSpecification){
            return JWS::fromCompactSerialization($spec->getCompactFormat());
        }
        throw new \RuntimeException('invalid JWE spec!');
    }
}