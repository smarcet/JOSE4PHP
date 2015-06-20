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

namespace jwk\impl;


use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwk\exceptions\InvalidJWKUseException;
use jwk\IJWK;
use jwk\JSONWebKeyParameters;
use jwk\JSONWebKeyPublicKeyUseValues;
use jwk\JSONWebKeyTypes;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;
use utils\JsonObject;

/**
 * Class JWK
 * @package jwk\impl
 */
abstract class JWK
    extends JsonObject
    implements  IJWK {

    /**
     * @param array $headers
     * @throws InvalidJWKAlgorithm
     * @throws InvalidJWKType
     * @throws InvalidJWKUseException
     */
    public function __construct(array $headers = array()){
        if(count($headers) === 0 ) return;
        $alg = @$headers[JSONWebKeyParameters::Algorithm];
        if(!in_array($alg, JSONWebSignatureAndEncryptionAlgorithms::$header_location_alg))
            throw new InvalidJWKAlgorithm (sprintf('alg %s', $alg));

        $this->set[JSONWebKeyParameters::Algorithm] = new StringOrURI($alg);

        $use = @$headers[JSONWebKeyParameters::PublicKeyUse];
        if(!in_array($use, JSONWebKeyPublicKeyUseValues::$valid_uses))
            throw new InvalidJWKUseException(sprintf('use %s', $use));

        $this->set[JSONWebKeyParameters::PublicKeyUse] = new StringOrURI($use);

        $id = @$headers[JSONWebKeyParameters::KeyId];
        if(!empty($id))
            $this->set[JSONWebKeyParameters::KeyId] = new  JsonValue($id);
    }

    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return  $this->set[JSONWebKeyParameters::Algorithm];
    }

    /**
     * @return string
     */
    public function getKeyUse()
    {
        return  $this->set[JSONWebKeyParameters::PublicKeyUse];
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->set[JSONWebKeyParameters::KeyId];
    }

}