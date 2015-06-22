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

namespace jwk\utils\rsa;

use jwk\utils\rsa\exceptions\RSABadPEMFormat;

/**
 * Class _RSAPublicKeyPEMFornat
 * @package jwk\utils\rsa
 */
class _RSAPublicKeyPEMFornat
    extends _AbstractRSAKeyPEMFornat
    implements RSAPublicKey {

    /**
     * @var \Math_BigInteger
     */
    private $e;

    /**
     * @param $pem_format
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format){
        parent::__construct($pem_format);
        $this->e = $this->rsa_imp->publicExponent;
    }

    /**
     * The "e" (exponent)
     * @return \Math_BigInteger
     */
    public function getPublicExponent()
    {
       return $this->e;
    }

    /**
     * @return string
     */
    public function getAlgorithm()
    {
       return 'RSA';
    }

    /**
     * @return string
     */
    public function getEncoded()
    {
        return $this->pem_format;
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return 'PKCS1';
    }

    /**
     * @return int
     */
    public function getBitLength()
    {
        return $this->rsa_imp->getSize();
    }
}