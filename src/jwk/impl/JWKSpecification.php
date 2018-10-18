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
use jwk\IJWKSpecification;
use jwk\JSONWebKeyPublicKeyUseValues;
/**
 * Class JWKSpecification
 * @package jwk\impl
 */
class JWKSpecification implements IJWKSpecification
{

    /**
     * @var string
     */
    protected $alg;

    /**
     * @var string
     */
    protected $use;

    /**
     * @var string
     */
    protected $kid;

    /**
     * @param string $alg
     * @param string $use
     * @param null|string $kid
     */
    public function __construct
    (
        $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256,
        $use = JSONWebKeyPublicKeyUseValues::Signature,
        $kid = null
    )
    {
        $this->alg  = $alg;
        $this->use  = $use;
        $this->kid  = $kid;
    }

    public function getAlg(){
        return $this->alg;
    }

    /**
     * https://tools.ietf.org/html/rfc7517#section-4.2
     *
     * The "use" (public key use) parameter identifies the intended use of
     * the public key.  The "use" parameter is employed to indicate whether
     * a public key is used for encrypting data or verifying the signature
     * on data.
     * @return string
     */
    public function getUse()
    {
       return $this->use;
    }

    /**
     * @return string
     */
    public function getKeyId()
    {
       return $this->kid;
    }
}