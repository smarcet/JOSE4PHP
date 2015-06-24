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

namespace jwe\impl;

use jwe\IJWE;
use jwk\exceptions\InvalidJWKType;
use jwk\IJWK;
use jwk\JSONWebKeyPublicKeyUseValues;
use jws\IJWSPayloadRawSpec;
use utils\json_types\StringOrURI;

/**
 * Class JWEFactory
 * @package jwe\impl
 */
final class JWEFactory {

    /**
     * @param IJWK $key
     * @param StringOrURI $enc
     * @param IJWSPayloadRawSpec $payload
     * @return IJWE
     * @throws InvalidJWKType
     */
    static public function build(IJWK $key, StringOrURI $enc, IJWSPayloadRawSpec $payload){


        if($key->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Encryption)
            throw new InvalidJWKType(sprintf('use % not supported (sig)',$key->getKeyUse()->getString()));

        $header = new JWEJOSEHeader($key->getAlgorithm(), $enc);

        $jwe = JWE::fromHeaderAndPayload($header, $payload);

        $jwe->setKey($key);

        return $jwe;
    }
}