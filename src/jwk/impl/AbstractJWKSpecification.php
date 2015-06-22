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

/**
 * Class AbstractJWKSpecification
 * @package jwk\impl
 */
abstract class AbstractJWKSpecification
    implements IJWKSpecification {


    /**
     * @var string
     */
    protected $alg;

    /**
     * @param string $alg
     */
    public function __construct($alg = JSONWebSignatureAndEncryptionAlgorithms::RS256){
        $this->alg = $alg;
    }

    public function getAlg(){
        return $this->alg;
    }
}