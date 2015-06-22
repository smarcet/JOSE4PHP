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

use jws\signing_algorithms\impl\JWSRSAAlgorithm;

/**
 * Class JWSRSAPS384Algorithm
 * @package jws\signing_algorithms\impl\rsa\PSS
 */
final class JWSRSAPS384Algorithm extends JWSRSAAlgorithm  {

    /**
     * @return int
     */
    protected function getMinKeyLen()
    {
        return 2048;
    }

    /**
     * @return string
     */
    protected function getAlgo()
    {
        return 'sha384';
    }

    /**
     * @return int
     */
    protected function getPaddingMode()
    {
        return CRYPT_RSA_SIGNATURE_PSS;
    }
}