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

namespace jws\signing_algorithms;

use jws\signing_algorithms\impl\hmac\JWSHA384Algorithm;
use jws\signing_algorithms\impl\hmac\JWSHA512Algorithm;
use jws\signing_algorithms\impl\JWSRSA256Algorithm;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jws\signing_algorithms\impl\JWSHS256Algorithm;
use jws\exceptions\JWSNotSupportedAlgorithm;
use jws\signing_algorithms\impl\rsa\JWSRSA384Algorithm;
use jws\signing_algorithms\impl\rsa\JWSRSA512Algorithm;
use jws\signing_algorithms\impl\rsa\PSS\JWSRSAPS256Algorithm;
use jws\signing_algorithms\impl\rsa\PSS\JWSRSAPS384Algorithm;
use jws\signing_algorithms\impl\rsa\PSS\JWSRSAPS512Algorithm;

/**
 * Class JWSAlgorithmRegistry
 * @package jws\signing_algorithms
 */
final class JWSAlgorithmRegistry {

    /**
     * @var JWSAlgorithmRegistry
     */
    private static $instance;

    private $set = array();


    private function __construct(){
        // HMAC with SHA-2 Functions
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS256] = new JWSHS256Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS384] = new JWSHA384Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS512] = new JWSHA512Algorithm;
        // Digital Signature with RSASSA-PKCS1-v1_5
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS256] = new JWSRSA256Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS384] = new JWSRSA384Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS512] = new JWSRSA512Algorithm;
        // Digital Signature with RSASSA-PSS
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS256] = new JWSRSAPS256Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS384] = new JWSRSAPS384Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS512] = new JWSRSAPS512Algorithm;
    }

    private function __clone(){}

    /**
     * @return JWSAlgorithmRegistry
     */
    public static function getInstance(){
        if(!is_object(self::$instance)){
            self::$instance = new JWSAlgorithmRegistry();
        }
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return IJWSAlgorithm
     * @throws JWSNotSupportedAlgorithm
     */
    public function getAlgorithm($alg){
        if(!array_key_exists($alg, $this->set))
            throw new JWSNotSupportedAlgorithm(sprintf('alg %s', $alg));
        return $this->set[$alg];
    }

}