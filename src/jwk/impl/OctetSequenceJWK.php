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
use jwk\exceptions\InvalidOctetSequenceJWKException;
use jwk\IJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jwk\JSONWebKeyParameters;
use jwk\JSONWebKeyPublicKeyUseValues;
use jwk\JSONWebKeyTypes;
use jwk\OctetSequenceKeysParameters;
use security\Key;
use utils\Base64UrlRepresentation;
use utils\json_types\StringOrURI;
/**
 * Class OctetSequenceJWK
 * @package jwk\impl
 */
final class OctetSequenceJWK extends JWK {

    /**
     * @var Key
     */
    private $key;

    protected function __construct(Key $secret, $headers = array())
    {

        if(empty($secret))
            throw new InvalidOctetSequenceJWKException('secret is not set!.');

        $this->set[JSONWebKeyParameters::KeyType] = new StringOrURI(JSONWebKeyTypes::OctetSequence);

        parent::__construct($headers);

        if(count($headers) === 0 ) return;

        $b64 = new Base64UrlRepresentation();

        $this->key = $secret;

        $this->set[OctetSequenceKeysParameters::Key] = new StringOrURI($b64->encode($secret->getStrippedEncoded()));

    }

    /**
     * @param string $key_op
     * @return Key
     */
    public function getKey($key_op = JSONWebKeyKeyOperationsValues::ComputeDigitalSignatureOrMAC)
    {
        return $this->key;
    }

    /**
     * @param Key $key
     * @param string $alg
     * @param string $use
     * @return IJWK
     */
    static public function fromSecret(Key $key, $alg = null, $use = JSONWebKeyPublicKeyUseValues::Signature){

        $headers = array();

        if(!empty($alg)) {

            $headers[JSONWebKeyParameters::Algorithm] = $alg;
        }

        $headers[JSONWebKeyParameters::PublicKeyUse] = $use;

        return new OctetSequenceJWK($key, $headers) ;
    }
}