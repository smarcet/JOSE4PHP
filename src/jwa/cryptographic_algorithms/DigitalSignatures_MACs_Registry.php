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
use jwa\cryptographic_algorithms\digital_signatures\DigitalSignatureAlgorithm;
use jwa\cryptographic_algorithms\macs\MAC_Algorithm;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwa\cryptographic_algorithms\macs\sha2\HS256_Algorithm;
use jwa\cryptographic_algorithms\macs\sha2\HS384_Algorithm;
use jwa\cryptographic_algorithms\macs\sha2\HS512_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PKCS1\RS256_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PKCS1\RS384_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PKCS1\RS512_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PSS\PS256_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PSS\PS384_Algorithm;
use jwa\cryptographic_algorithms\digital_signatures\rsa\PSS\PS512_Algorithm;
/**
 * Class DigitalSignatures_MACs_Registry
 * @package jwa\cryptographic_algorithms
 */
final class DigitalSignatures_MACs_Registry {

    /**
     * @var DigitalSignatures_MACs_Registry
     */
    private static $instance;

    private $algorithms = [];

    private function __construct(){

        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::HS256] = new HS256_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::HS384] = new HS384_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::HS512] = new HS512_Algorithm;

        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RS256] = new RS256_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RS384] = new RS384_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::RS512] = new RS512_Algorithm;

        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::PS256] = new PS256_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::PS384] = new PS384_Algorithm;
        $this->algorithms[JSONWebSignatureAndEncryptionAlgorithms::PS512] = new PS512_Algorithm;

    }

    private function __clone(){}

    /**
     * @return DigitalSignatures_MACs_Registry
     */
    public static function getInstance(){
        if(!is_object(self::$instance)){
            self::$instance = new DigitalSignatures_MACs_Registry();
        }
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return bool
     */
    public function isSupported($alg){
        return array_key_exists($alg, $this->algorithms);
    }

    /**
     * @param $alg
     * @return null|DigitalSignatureAlgorithm|MAC_Algorithm
     */
    public function get($alg){
        if(!$this->isSupported($alg)) return null;
        return $this->algorithms[$alg];
    }
}