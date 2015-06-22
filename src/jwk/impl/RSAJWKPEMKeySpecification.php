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
use jwk\IJWKSpecification;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;

/**
 * Class RSAJWKPEMKeySpecification
 * @package jwk\impl
 */
abstract class RSAJWKPEMKeySpecification
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
    private $key_pem;

    /**
     * @param string $key_pem
     * @param string $alg
     */
    public function __construct($key_pem, $alg = JSONWebSignatureAndEncryptionAlgorithms::RS256){
        parent::__construct($alg);
        $this->key_pem = $key_pem;
    }

    public function getPEM(){
        return $this->key_pem;
    }

}