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


use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jws\exceptions\JWSNotSupportedAlgorithm;
// HMAC with SHA-2 Functions
use jws\signing_algorithms\impl\hmac\JWS_HS256_Algorithm;
use jws\signing_algorithms\impl\hmac\JWS_HS384_Algorithm;
use jws\signing_algorithms\impl\hmac\JWS_HS512_Algorithm;
// Digital Signature with RSASSA-PKCS1-v1_5
use jws\signing_algorithms\impl\rsa\PKCS1\JWS_RS256_Algorithm;
use jws\signing_algorithms\impl\rsa\PKCS1\JWS_RS384_Algorithm;
use jws\signing_algorithms\impl\rsa\PKCS1\JWS_RS512_Algorithm;
// Digital Signature with RSASSA-PSS
use jws\signing_algorithms\impl\rsa\PSS\JWS_PS256_Algorithm;
use jws\signing_algorithms\impl\rsa\PSS\JWS_PS384_Algorithm;
use jws\signing_algorithms\impl\rsa\PSS\JWS_PS512_Algorithm;


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
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS256] = new JWS_HS256_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS384] = new JWS_HS384_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::HS512] = new JWS_HS512_Algorithm;
        // Digital Signature with RSASSA-PKCS1-v1_5
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS256] = new JWS_RS256_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS384] = new JWS_RS384_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::RS512] = new JWS_RS512_Algorithm;
        // Digital Signature with RSASSA-PSS
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS256] = new JWS_PS256_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS384] = new JWS_PS384_Algorithm;
        $this->set[JSONWebSignatureAndEncryptionAlgorithms::PS512] = new JWS_PS512_Algorithm;
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