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
use jwe\IJWE_CompactFormatSpecification;
use jwe\IJWE_ParamsSpecification;
use jwe\IJWE_Specification;
use jwk\exceptions\InvalidJWKType;
use jwk\JSONWebKeyPublicKeyUseValues;

/**
 * Class JWEFactory
 * @package jwe\impl
 */
final class JWEFactory {


    /**
     * @param IJWE_Specification $spec
     * @return IJWE
     * @throws InvalidJWKType
     */
    static public function build(IJWE_Specification $spec){


        if($spec instanceof IJWE_ParamsSpecification){

            if($spec->getRecipientKey()->getKeyUse()->getString() !== JSONWebKeyPublicKeyUseValues::Encryption)
                throw new InvalidJWKType(sprintf('use %s not supported (should be "enc")', $spec->getRecipientKey()->getKeyUse()->getString()));

            $header = new JWEJOSEHeader($spec->getAlg(), $spec->getEnc());

            //set zip alg
            $zip    = $spec->getZip();
            if(!is_null($zip))
                $header->setCompressionAlgorithm($zip);

            $jwe = JWE::fromHeaderAndPayload($header, $spec->getPayload());

            $jwe->setRecipientKey($spec->getRecipientKey());

            return $jwe;
        }
        if($spec instanceof IJWE_CompactFormatSpecification){
            return JWE::fromCompactSerialization($spec->getCompactFormat());
        }
        throw new \RuntimeException('invalid JWE spec!');
    }
}