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
use jwk\IJWKSpecification;
use jwk\JSONWebKeyPublicKeyUseValues;
use utils\json_types\Base64urlUInt;

/**
 * Class RSAJWKParamsPublicKeySpecification
 * @package jwk\impl
 */
final class RSAJWKParamsPublicKeySpecification
    extends AbstractJWKSpecification
    implements IJWKSpecification {

    /**
     * @return int
     */
    public function getKeyLenInBits()
    {
        return 2048;
    }

    /**
     * @var string
     */
    private $n_b64;

    /**
     * @var string
     */
    private $e_b64;

    /**
     * @param string $n_b64
     * @param string $e_b64
     * @param string $alg
     * @param string $use
     */
    public function __construct($n_b64, $e_b64, $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256, $use = JSONWebKeyPublicKeyUseValues::Signature){
        parent::__construct($alg, $use);
        $this->e_b64 = $e_b64;
        $this->n_b64 = $n_b64;
    }

    /**
     * @return Base64urlUInt
     */
    public function getModulus(){
        return new Base64urlUInt($this->n_b64);
    }

    /**
     * @return Base64urlUInt
     */
    public function getExponent(){
        return new Base64urlUInt($this->e_b64);
    }
}