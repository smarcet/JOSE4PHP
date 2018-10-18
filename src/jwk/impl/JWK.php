<?php namespace jwk\impl;
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
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwk\exceptions\InvalidJWKAlgorithm;
use jwk\exceptions\InvalidJWKType;
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
    protected function __construct(array $headers = []){

        if(count($headers) === 0 ) return;

        $alg = @$headers[JSONWebKeyParameters::Algorithm];
        $this->setAlgorithm($alg);

        $use = @$headers[JSONWebKeyParameters::PublicKeyUse];
        $this->setKeyUse($use);

        $id = @$headers[JSONWebKeyParameters::KeyId];
        $this->setId($id);
    }

    /**
     * @return StringOrURI
     */
    public function getAlgorithm()
    {
        return  $this[JSONWebKeyParameters::Algorithm];
    }

    /**
     * @return StringOrURI
     */
    public function getKeyUse()
    {
        return  $this[JSONWebKeyParameters::PublicKeyUse];
    }

    /**
     * @return JsonValue
     */
    public function getId()
    {
        return $this[JSONWebKeyParameters::KeyId];
    }

    /**
     * @param  JsonValue $kid
     * @return $this
     */
    public function setId($kid)
    {
        if(!empty($kid))
            $this->set[JSONWebKeyParameters::KeyId] = new  JsonValue($kid);
        return $this;
    }

    /**
     * @param string $alg
     * @throws InvalidJWKAlgorithm
     * @return $this
     */
    public function setAlgorithm($alg)
    {
        if(!in_array($alg, JSONWebSignatureAndEncryptionAlgorithms::$header_location_alg))
            throw new InvalidJWKAlgorithm (sprintf('alg %s', $alg));

        $this->set[JSONWebKeyParameters::Algorithm] = new StringOrURI($alg);
        return $this;
    }

    /**
     * @param string $use
     * @throws InvalidJWKUseException
     * @return $this
     */
    public function setKeyUse($use)
    {
        if(empty($use)) return $this;
        if(!in_array($use, JSONWebKeyPublicKeyUseValues::$valid_uses))
            throw new InvalidJWKUseException(sprintf('use %s', $use));

        $this->set[JSONWebKeyParameters::PublicKeyUse] = new StringOrURI($use);
        return $this;
    }

    /**
     * @param string $type
     * @throws InvalidJWKType
     * @return $this
     */
    public function setType($type)
    {
        if(!in_array($type, JSONWebKeyTypes::$valid_keys_set))
            throw new InvalidJWKType(sprintf('use %s', $type));

        $this->set[JSONWebKeyParameters::KeyType] = new StringOrURI($type);
        return $this;
    }

    /**
     * @return StringOrURI
     */
    public function getType()
    {
        return  $this[JSONWebKeyParameters::KeyType];
    }
}