<?php namespace jwa\cryptographic_algorithms\digital_signatures\rsa\PSS;
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
/**
 * Class PS256_Algorithm
 * @package jwa\cryptographic_algorithms\digital_signatures\rsa\PSS
 */
final class PS256_Algorithm extends RSASSA_PSS_Algorithm {

    /**
     * @return string
     */
    public function getHashingAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return string
     */
    public function getName()
    {
        return JSONWebSignatureAndEncryptionAlgorithms::PS256;
    }

    /**
     * hash key size in bits
     * @return int
     */
    public function getHashKeyLen()
    {
        return 256;
    }
}