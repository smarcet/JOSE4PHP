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


use jwk\exceptions\InvalidJWKAlgorithm;
use jwk\exceptions\RSAJWKMissingPrivateKeyParamException;
use jwk\exceptions\RSAJWKMissingPublicKeyParamException;
use jwk\IAsymetricJWK;
use jwk\JSONWebKeyParameters;
use jwk\JSONWebKeyTypes;
use jwk\JSONWebKeyVisibility;
use jwk\RSAKeysParameters;
use jwk\utils\Key;
use jwk\utils\KeyPair;
use jwk\utils\PrivateKey;
use jwk\utils\PublicKey;
use jwk\utils\rsa\RSAFacade;
use jwk\utils\rsa\RSAPrivateKey;
use jwk\utils\rsa\RSAPublicKey;
use utils\json_types\Base64urlUInt;
use utils\json_types\StringOrURI;

/**
 * Class RSAJWK
 * @package jwk\impl
 */
final class RSAJWK extends AsymetricJWK {

    /**
     * @param array $headers
     * @throws RSAJWKMissingPrivateKeyParamException
     * @throws RSAJWKMissingPublicKeyParamException
     */
    protected function __construct($headers = array()){

        $this->set[JSONWebKeyParameters::KeyType] = new StringOrURI(JSONWebKeyTypes::RSA);

        parent::__construct($headers);

        if(count($headers) === 0 ) return;

        foreach(RSAKeysParameters::$public_key_params as $p){
            if(!array_key_exists($p, $headers))
                throw new RSAJWKMissingPublicKeyParamException();
            $this->set[$p] = new Base64urlUInt($headers[$p]);
        }

        $this->visibility = JSONWebKeyVisibility::PublicOnly;

        //calculate public key
        $this->public_key = RSAFacade::getInstance()->buildPublicKey($this[RSAKeysParameters::Modulus]->toBigInt(), $this[RSAKeysParameters::Exponent]->toBigInt());

        if(in_array(RSAKeysParameters::PrivateExponent, $headers)){
            // its a private key
            $this->visibility = JSONWebKeyVisibility::IncludePrivate;

            $this[RSAKeysParameters::PrivateExponent] = new Base64urlUInt($headers[RSAKeysParameters::PrivateExponent]);
            //its has one private param, must have all ...
            if(in_array(RSAKeysParameters::FirstPrimeFactor, $headers)){
               foreach (RSAKeysParameters::$producers_private_key_params as $p) {
                   if (!array_key_exists($p, $headers))
                        throw new RSAJWKMissingPrivateKeyParamException();
                   $this->set[$p] = new Base64urlUInt($headers[$p]);
                }
                $this->private_key = RSAFacade::getInstance()->buildPrivateKey(
                    $this[RSAKeysParameters::Modulus]->toBigInt(),
                    $this[RSAKeysParameters::Exponent]->toBigInt(),
                    $this[RSAKeysParameters::PrivateExponent]->toBigInt(),
                    $this[RSAKeysParameters::FirstPrimeFactor]->toBigInt(),
                    $this[RSAKeysParameters::SecondPrimeFactor]->toBigInt(),
                    $this[RSAKeysParameters::FirstFactorCRTExponent]->toBigInt(),
                    $this[RSAKeysParameters::SecondFactorCRTExponent]->toBigInt(),
                    $this[RSAKeysParameters::FirstCRTCoefficient]->toBigInt()
                );
            }
            else{
               $this->private_key = RSAFacade::getInstance()->buildMinimalPrivateKey(
                   $this[RSAKeysParameters::Modulus]->toBigInt(),
                   $this[RSAKeysParameters::PrivateExponent]->toBigInt()
               );
            }

        }
    }

    /**
     * @return string
     */
    public function getType()
    {
       return JSONWebKeyTypes::RSA;
    }

    /**
     * @param KeyPair $keys
     * @return IAsymetricJWK
     */
    static public function fromKeys(KeyPair $keys){

        $jwk = new RSAJWK();
        $jwk->public_key  = $keys->getPublic();
        $jwk->private_key = $keys->getPrivate();
        $jwk->set[RSAKeysParameters::Exponent] = Base64urlUInt::fromBigInt( $jwk->public_key->getPublicExponent());
        $jwk->set[RSAKeysParameters::Modulus]  = Base64urlUInt::fromBigInt( $jwk->public_key->getModulus());
        $jwk->set[RSAKeysParameters::PrivateExponent] = Base64urlUInt::fromBigInt($jwk->private_key->getPrivateExponent());
        return $jwk;
    }

    /**
     * @param PublicKey $public_key
     * @return IAsymetricJWK
     */
    static public function fromPublicKey(PublicKey $public_key){
        if($public_key instanceof RSAPublicKey) {
            $jwk = new RSAJWK();
            $jwk->public_key = $public_key;
            $jwk->set[RSAKeysParameters::Exponent] = Base64urlUInt::fromBigInt($public_key->getPublicExponent());
            $jwk->set[RSAKeysParameters::Modulus]  = Base64urlUInt::fromBigInt($public_key->getModulus());
            return $jwk;
        }
        return null;
    }

    /**
     * @param PrivateKey $private_key
     * @return IAsymetricJWK|null
     */
    static public function fromPrivateKey(PrivateKey $private_key){
        if($private_key instanceof RSAPrivateKey) {
            $jwk = new RSAJWK();
            $jwk->private_key = $private_key;
            $jwk->set[RSAKeysParameters::Exponent]        = Base64urlUInt::fromBigInt($private_key->getPublicExponent());
            $jwk->set[RSAKeysParameters::Modulus]         = Base64urlUInt::fromBigInt($private_key->getModulus());
            $jwk->set[RSAKeysParameters::PrivateExponent] = Base64urlUInt::fromBigInt($private_key->getPrivateExponent());
            return $jwk;
        }
        return null;
    }


    /**
     * @return Key
     */
    public function getKey()
    {
        return $this->getPrivateKey();
    }

    /**
     * @param string $alg
     * @throws InvalidJWKAlgorithm
     * @return $this
     */
    public function setAlgorithm($alg)
    {
        if(!in_array($alg, RSAKeysParameters::$valid_algorithms_values))
            throw new InvalidJWKAlgorithm(sprintf('alg %s not supported on RSA KEY!', $alg));
        return parent::setAlgorithm($alg);
    }
}