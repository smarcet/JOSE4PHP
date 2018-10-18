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
use jwk\exceptions\JWKInvalidIdentifierException;
use jwk\IJWK;
use jwk\IJWKSet;
use jwk\JSONWebKeyParameters;
use jwk\JSONWebKeyTypes;
use jwk\JWKSetParameters;
use jwk\PublicJSONWebKeyParameters;
use jwk\RSAKeysParameters;
use utils\json_types\JsonArray;
use utils\JsonObject;
/**
 * Class JWKSet
 * @package jwk\impl
 */
final class JWKSet
    extends JsonObject
    implements IJWKSet {


    private $keys_ids = array();

    /**
     * @param JWK[] $keys
     * @throws JWKInvalidIdentifierException
     */
    public function __construct(array $keys = array()){

        $this->set[JWKSetParameters::Keys] = new JsonArray(array());

        foreach($keys as $k){
            $this->addKey($k);
        }
    }

    /**
     * @return IJWK[]
     */
    public function getKeys()
    {
        if(isset($this->set[JWKSetParameters::Keys]))
            return $this->set[JWKSetParameters::Keys]->getValue();
        return array();
    }

    /**
     * @param IJWK $key
     * @return void
     * @throws JWKInvalidIdentifierException
     */
    public function addKey(IJWK $key)
    {
        $id = $key->getId();

        if(empty($id))
            throw new JWKInvalidIdentifierException('key id is empty!');

        if(array_key_exists($id->getValue(), $this->keys_ids))
            throw new JWKInvalidIdentifierException(sprintf('id %s already exists!'), $key->getId()->getValue());

        if(!isset($this->set[JWKSetParameters::Keys]))
            $this->set[JWKSetParameters::Keys] = new JsonArray(array());

        $keys = $this->set[JWKSetParameters::Keys];
        $keys->append($key);
        $this->set[JWKSetParameters::Keys] = $keys ;
        $this->keys_ids[$id->getValue()] = $key;
    }

    /**
     * @param string $kid
     * @return IJWK
     */
    public function getKeyById($kid)
    {
        if(!array_key_exists($kid, $this->keys_ids)) return null;
        return $this->keys_ids[$kid];
    }

    /**
     * @param $json
     * @return IJWKSet
     * @throws InvalidJWKAlgorithm
     * @throws JWKInvalidIdentifierException
     */
    static public function fromJson($json){
        $json = str_replace( array("\n","\r","\t"), '', trim($json));
        $res  = json_decode($json, true);
        if(!isset($res[JWKSetParameters::Keys])) throw new JWKInvalidIdentifierException;
        $keys = $res[JWKSetParameters::Keys];
        $jwk_set = new JWKSet;
        foreach($keys as $key){
            $kty = @$key[JSONWebKeyParameters::KeyType];
            $kid = @$key[JSONWebKeyParameters::KeyId];
            $use = @$key[JSONWebKeyParameters::PublicKeyUse];
            $alg = @$key[JSONWebKeyParameters::Algorithm];
            if(empty($alg)) $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256;

            if(empty($kty) || empty($kid) || empty($use)) continue;

            if(!in_array($kty, JSONWebKeyTypes::$supported_keys)) continue;

            $n        = @$key[RSAKeysParameters::Modulus];
            $e        = @$key[RSAKeysParameters::Exponent];
            $x5c      = @$key[PublicJSONWebKeyParameters::X_509CertificateChain];
            if(is_null($x5c)) $x5c = array();
            $x5u      = @$key[PublicJSONWebKeyParameters::X_509Url];
            $x5t      = @$key[PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint];
            $x5t_S256 = @$key[PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint];

           $jwk = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification(
                $n,
                $e,
                $alg,
                $use,
                $x5c,
                $x5u,
                $x5t,
                $x5t_S256,
                $kid
            ));

            $jwk_set->addKey($jwk);

        }
        return $jwk_set;
    }

}