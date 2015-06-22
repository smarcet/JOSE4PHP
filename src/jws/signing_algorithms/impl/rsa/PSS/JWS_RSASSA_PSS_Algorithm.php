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

namespace jws\signing_algorithms\impl\rsa\PSS;

use jws\signing_algorithms\impl\rsa\JWS_RSA_Algorithm;

/**
 * Class JWS_RSASSA_PSS_Algorithm
 * @package jws\signing_algorithms\impl\rsa\PSS
 */
abstract class JWS_RSASSA_PSS_Algorithm extends JWS_RSA_Algorithm {

    /**
     * @return int
     */
    protected function getPaddingMode()
    {
        return CRYPT_RSA_SIGNATURE_PSS;
    }

    /**
     * @return int
     */
    protected function getMinKeyLen()
    {
        return 2048;
    }
}