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
use jwk\exceptions\InvalidJWKType;
use jwk\exceptions\InvalidJWKUseException;
use jwk\exceptions\RSAJWKMissingPrivateKeyParamException;
use jwk\exceptions\RSAJWKMissingPublicKeyParamException;
use jwk\IAsymmetricJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jwk\JSONWebKeyParameters;
use jwk\JSONWebKeyTypes;
use jwk\JSONWebKeyVisibility;
use jwk\RSAKeysParameters;
use security\Key;
use security\KeyPair;
use security\PrivateKey;
use security\PublicKey;
use security\rsa\RSAFacade;
use security\rsa\RSAPrivateKey;
use security\rsa\RSAPublicKey;
use utils\json_types\Base64urlUInt;
use utils\json_types\StringOrURI;
/**
 * Class RSAJWK
 * @package jwk\impl
 */
final class RSAJWK extends AsymmetricJWK
{

    /**
     * @param array $headers
     * @throws RSAJWKMissingPrivateKeyParamException
     * @throws RSAJWKMissingPublicKeyParamException
     */
    protected function __construct($headers = array())
    {

        $this->set[JSONWebKeyParameters::KeyType] = new StringOrURI(JSONWebKeyTypes::RSA);

        parent::__construct($headers);

        if (count($headers) === 0) return;

        foreach (RSAKeysParameters::$public_key_params as $p) {
            if (!array_key_exists($p, $headers))
                throw new RSAJWKMissingPublicKeyParamException();
            $this->set[$p] = new Base64urlUInt($headers[$p]);
        }

        $this->visibility = JSONWebKeyVisibility::PublicOnly;

        //calculate public key
        $this->public_key = RSAFacade::getInstance()->buildPublicKey($this[RSAKeysParameters::Modulus]->toBigInt(), $this[RSAKeysParameters::Exponent]->toBigInt());

        if (in_array(RSAKeysParameters::PrivateExponent, $headers)) {
            // its a private key
            $this->visibility = JSONWebKeyVisibility::IncludePrivate;

            $this[RSAKeysParameters::PrivateExponent] = new Base64urlUInt($headers[RSAKeysParameters::PrivateExponent]);
            //its has one private param, must have all ...
            if (in_array(RSAKeysParameters::FirstPrimeFactor, $headers)) {
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
            } else {
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
     * @return IAsymmetricJWK
     */
    static public function fromKeys(KeyPair $keys)
    {
        if(!($keys->getPrivate() instanceof RSAPrivateKey))
            throw new \RuntimeException('Private key of invalid type!');

        if(!($keys->getPublic() instanceof RSAPublicKey))
            throw new \RuntimeException('Public key of invalid type!');

        $jwk                                          = new RSAJWK();
        $jwk->public_key                              = $keys->getPublic();
        $jwk->private_key                             = $keys->getPrivate();
        $jwk->set[RSAKeysParameters::Exponent]        = Base64urlUInt::fromBigInt($jwk->public_key->getPublicExponent());
        $jwk->set[RSAKeysParameters::Modulus]         = Base64urlUInt::fromBigInt($jwk->public_key->getModulus());
        $jwk->set[RSAKeysParameters::PrivateExponent] = Base64urlUInt::fromBigInt($jwk->private_key->getPrivateExponent());
        return $jwk;
    }

    /**
     * @param PublicKey $public_key
     * @return IAsymmetricJWK
     * @throws InvalidJWKType
     */
    static public function fromPublicKey(PublicKey $public_key)
    {
        if (!($public_key instanceof RSAPublicKey)) throw new InvalidJWKType();
        $jwk = new RSAJWK();
        $jwk->public_key = $public_key;
        $jwk->set[RSAKeysParameters::Exponent] = Base64urlUInt::fromBigInt($public_key->getPublicExponent());
        $jwk->set[RSAKeysParameters::Modulus] = Base64urlUInt::fromBigInt($public_key->getModulus());
        return $jwk;
    }

    /**
     * @param PrivateKey $private_key
     * @return IAsymmetricJWK|null
     * @throws InvalidJWKType
     */
    static public function fromPrivateKey(PrivateKey $private_key)
    {
        if (!($private_key instanceof RSAPrivateKey)) throw new InvalidJWKType();
        $jwk = new RSAJWK();
        $jwk->private_key = $private_key;
        $jwk->set[RSAKeysParameters::Exponent] = Base64urlUInt::fromBigInt($private_key->getPublicExponent());
        $jwk->set[RSAKeysParameters::Modulus] = Base64urlUInt::fromBigInt($private_key->getModulus());
        $jwk->set[RSAKeysParameters::PrivateExponent] = Base64urlUInt::fromBigInt($private_key->getPrivateExponent());
        return $jwk;
    }

    /**
     * @param string $key_op
     * @return Key
     * @throws InvalidJWKUseException
     */
    public function getKey($key_op = JSONWebKeyKeyOperationsValues::ComputeDigitalSignatureOrMAC)
    {
        switch($key_op){
            case JSONWebKeyKeyOperationsValues::ComputeDigitalSignatureOrMAC:
            case JSONWebKeyKeyOperationsValues::DecryptContentAndValidateDecryption: {
                return $this->getPrivateKey();
            }
            break;
            case JSONWebKeyKeyOperationsValues::VerifyDigitalSignatureOrMAC:
            case JSONWebKeyKeyOperationsValues::EncryptContent: {
                return $this->getPublicKey();
            }
            break;
            default:{
                throw new InvalidJWKUseException(sprintf('key_op %s',  $key_op));
            }
            break;
        }
    }

    /**
     * @override
     * @return array
     */
    public function toArray()
    {
        $res = parent::toArray();
        if($this->visibility === JSONWebKeyVisibility::PublicOnly){
            //remove private attributes
            unset($res[RSAKeysParameters::PrivateExponent]);
            unset($res[RSAKeysParameters::FirstPrimeFactor]);
            unset($res[RSAKeysParameters::SecondPrimeFactor]);
            unset($res[RSAKeysParameters::FirstFactorCRTExponent]);
            unset($res[RSAKeysParameters::SecondFactorCRTExponent]);
            unset($res[RSAKeysParameters::FirstCRTCoefficient]);
        }
        return $res;
    }

}