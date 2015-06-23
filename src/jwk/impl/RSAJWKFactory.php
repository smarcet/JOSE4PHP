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

use jwk\IJWK;
use jwk\IJWKFactory;
use jwk\IJWKSpecification;
use jwk\utils\KeyPair;
use \jwk\utils\rsa\RSAFacade;

/**
 * Class RSAJWKFactory
 * @package jwk\impl
 */
final class RSAJWKFactory implements IJWKFactory
{

    /**
     * @param IJWKSpecification $spec
     * @return IJWK
     */
    static public function build(IJWKSpecification $spec)
    {
        if ($spec instanceof RSAJWKKeyLengthSpecification) {
            $keys = RSAFacade::getInstance()->buildKeyPair($spec->getKeyLenInBits());
            $jwk  = RSAJWK::fromKeys($keys);
            $jwk->setAlgorithm($spec->getAlg());
            $jwk->setKeyUse($spec->getUse());
            return $jwk;
        }
        if ($spec instanceof RSAJWKPEMPrivateKeySpecification) {
            $private_key  = RSAFacade::getInstance()->buildPrivateKeyFromPEM($spec->getPEM());
            $public_key   = RSAFacade::getInstance()->buildPublicKey($private_key->getModulus(), $private_key->getPublicExponent());
            $jwk = RSAJWK::fromKeys(new KeyPair($public_key, $private_key));
            $jwk->setAlgorithm($spec->getAlg());
            $jwk->setKeyUse($spec->getUse());
            return $jwk;
        }
        if($spec instanceof RSAJWKParamsPublicKeySpecification){
            $public_key = RSAFacade::getInstance()->buildPublicKey($spec->getModulus()->toBigInt(), $spec->getExponent()->toBigInt());
            $jwk = RSAJWK::fromPublicKey($public_key);
            $jwk->setAlgorithm($spec->getAlg());
            $jwk->setKeyUse($spec->getUse());
            return $jwk;
        }
        if($spec instanceof RSAJWKPEMPublicKeySpecification){
            $public_key = RSAFacade::getInstance()->buildPublicKeyFromPEM($spec->getPEM());
            $jwk = RSAJWK::fromPublicKey($public_key);
            $jwk->setAlgorithm($spec->getAlg());
            $jwk->setKeyUse($spec->getUse());
            return $jwk;
        }
        return null;
    }

}