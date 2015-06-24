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
 * Class _AbstractRSAKeyPEMFornat
 * @package security\rsa
 */
abstract class _AbstractRSAKeyPEMFornat {

    /**
     * @var string
     */
    protected $pem_format;

    /**
     * @var \Crypt_RSA
     */
    protected $rsa_imp;

    /**
     * @var \Math_BigInteger
     */
    protected $n;


    /**
     * @param $pem_format
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format){

        $this->pem_format = $pem_format;
        $this->rsa_imp    = new \Crypt_RSA();

        $res = $this->rsa_imp->loadKey($this->pem_format, CRYPT_RSA_PRIVATE_FORMAT_PKCS1);

        if(!$res) throw new RSABadPEMFormat(sprintf('pem %s',$pem_format ));

        $this->n = $this->rsa_imp->modulus;
    }

    /**
     * Returns The "n" (modulus)
     * @return \Math_BigInteger
     */
    public function getModulus()
    {
        return  $this->n;
    }

}