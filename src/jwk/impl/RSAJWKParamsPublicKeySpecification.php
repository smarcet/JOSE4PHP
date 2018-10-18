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
use jwk\JSONWebKeyPublicKeyUseValues;
use utils\json_types\Base64urlUInt;
/**
 * Class RSAJWKParamsPublicKeySpecification
 * @package jwk\impl
 */
final class RSAJWKParamsPublicKeySpecification extends RSAJWKSpecification
{

    /**
     * @var string
     */
    private $n_b64;

    /**
     * @var string
     */
    private $e_b64;


    /**
     * @var array
     */
    private $x5c;

    /**
     * @var string
     */
    private $x5u;

    /**
     * @var string
     */
    private $x5t;

    /**
     * @var string
     */
    private $x5t_S256;


    /**
     * @param string $n_b64
     * @param string $e_b64
     * @param string $alg
     * @param string $use
     * @param array $x5c
     * @param null $x5u
     * @param null $x5t
     * @param null $x5t_S256
     * @param null $kid
     * @throws \jwk\exceptions\InvalidJWKAlgorithm
     */
    public function __construct(
        $n_b64,
        $e_b64,
        $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256,
        $use = JSONWebKeyPublicKeyUseValues::Signature,
        $x5c = array(),
        $x5u = null,
        $x5t = null,
        $x5t_S256 = null,
        $kid = null
    ) {
        parent::__construct($alg, $use, $kid);
        $this->n_b64    = $n_b64;
        $this->e_b64    = $e_b64;
        $this->x5c      = $x5c;
        $this->x5u      = $x5u;
        $this->x5t      = $x5t;
        $this->x5t_S256 = $x5t_S256;
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

    /**
     * @return array
     */
    public function getX509CertificateChain(){
        return $this->x5c;
    }

    /**
     * @return null|string
     */
    public function getX509Url(){
        return $this->x5u;
    }

    /**
     * @return null|string
     */
    public function getX509CertificateSHA_1_Thumbprint(){
        return $this->x5t;
    }

    /**
     * @return null|string
     */
    public function getX509CertificateSHA_256_Thumbprint(){
        return $this->x5t_S256;
    }
}