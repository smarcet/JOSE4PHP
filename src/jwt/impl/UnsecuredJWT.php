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

namespace jwt\impl;

use jwt\IJWTClaimSet;
use utils\json_types\StringOrURI;

/**
 * Class UnsecuredJWT
 * @package jwt\impl
 *
 * https://tools.ietf.org/html/rfc7519#section-6
 *
 *
 */
class UnsecuredJWT extends JWT {

    const EmptySignature = '';

    /**
     * @param IJWTClaimSet $claimSet
     */
    public function __construct(IJWTClaimSet $claimSet){

        $this->header    = new JOSEHeader(new StringOrURI('none'), new StringOrURI('JWT'));
        $this->claimSet  = $claimSet;
        $this->signature = self::EmptySignature;
    }

    /**
     * @param $private_key_or_secret
     * @param string $algorithm
     * @return mixed
     */
    public function sign($private_key_or_secret, $algorithm = 'HS256')
    {

    }

    /**
     * @param $public_key_or_secret
     * @param null $alg
     * @return mixed
     */
    public function verify($public_key_or_secret, $alg = null)
    {

    }

    /**
     * @param $public_key_or_secret
     * @param string $algorithm
     * @param string $encryption_method
     * @return mixed
     */
    public function encrypt($public_key_or_secret, $algorithm = 'RSA1_5', $encryption_method = 'A128CBC-HS256')
    {

    }

    /**
     * @param $private_key_or_secret
     * @return mixed
     */
    public function decrypt($private_key_or_secret)
    {

    }
}