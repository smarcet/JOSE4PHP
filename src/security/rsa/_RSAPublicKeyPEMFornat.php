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

namespace security\rsa;

use security\rsa\exceptions\RSABadPEMFormat;

/**
 * Class _RSAPublicKeyPEMFornat
 * @package security\rsa
 */
class _RSAPublicKeyPEMFornat
    extends _AbstractRSAKeyPEMFornat
    implements RSAPublicKey {

    /**
     * @var \Math_BigInteger
     */
    protected $e;

    /**
     * @param $pem_format
     * @param string $password
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format, $password = null){
        parent::__construct($pem_format, $password);
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
        $pem = $this->rsa_imp->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS8);
        $pem = preg_replace('/\-+BEGIN PUBLIC KEY\-+/','',$pem);
        $pem = preg_replace('/\-+END PUBLIC KEY\-+/','',$pem);
        $pem = str_replace( array("\n","\r","\t"), '', trim($pem));
        return $pem;
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return 'PKCS8';
    }

    /**
     * @return int
     */
    public function getBitLength()
    {
        return $this->rsa_imp->getSize();
    }
}