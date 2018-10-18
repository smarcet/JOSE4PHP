<?php namespace jwa\cryptographic_algorithms;
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
use jwk\JSONWebKeyTypes;
use phpseclib\Crypt\RSA;
/**
 * Class Abstract_RSA_Algorithm
 * @package jwa\cryptographic_algorithms
 */
abstract class Abstract_RSA_Algorithm implements ICryptoAlgorithm {

    /**
     * @var RSA
     */
    protected $rsa_impl;

    public function __construct() {
        $this->rsa_impl = new RSA();
    }

    /**
     * @return string
     */
    public function getKeyType()
    {
        return JSONWebKeyTypes::RSA;
    }

    /**
     * @return int
     */
    public function getMinKeyLen()
    {
        return 2048;
    }
}