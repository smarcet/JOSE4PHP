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
/**
 * Class RSAJWKPEMPrivateKeySpecification
 * @package jwk\impl
 */
final class RSAJWKPEMPrivateKeySpecification extends RSAJWKPEMKeySpecification
{

    const WithoutPassword = null;
    /**
     * @var string
     */
    private $password;

    /**
     * @param string $key_pem
     * @param string $password
     * @param string $alg
     * @param string $use
     */
    public function __construct
    (
        $key_pem,
        $password = self::WithoutPassword,
        $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256,
        $use = JSONWebKeyPublicKeyUseValues::Signature
    )
    {
        parent::__construct($key_pem , $alg, $use);
        $this->password = $password;
    }
    /**
     * @return string
     */
    public function getPrivateKeyPEM()
    {
        return $this->getPEM();
    }

    /**
     * @return null|string
     */
    public function getPrivateKeyPassword()
    {
        return $this->password;
    }
}