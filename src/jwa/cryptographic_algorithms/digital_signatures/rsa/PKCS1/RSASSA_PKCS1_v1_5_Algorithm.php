<?php namespace jwa\cryptographic_algorithms\digital_signatures\rsa\PKCS1;
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
use jwa\cryptographic_algorithms\digital_signatures\rsa\RSA_Algorithm;
use phpseclib\Crypt\RSA;
/**
 * Class RSASSA_PKCS1_v1_5_Algorithm
 * @package jwa\cryptographic_algorithms\digital_signatures\rsa\PKCS1
 */
abstract class RSASSA_PKCS1_v1_5_Algorithm extends RSA_Algorithm {

    /**
     * @return int
     */
    public function getPaddingMode()
    {
        return RSA::SIGNATURE_PKCS1 ;
    }
}