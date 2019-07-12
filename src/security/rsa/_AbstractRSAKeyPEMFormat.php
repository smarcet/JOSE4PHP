<?php namespace security\rsa;
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
use security\rsa\exceptions\RSABadPEMFormat;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
/**
 * Class _AbstractRSAKeyPEMFormat
 * @package security\rsa
 */
abstract class _AbstractRSAKeyPEMFormat {

    /**
     * @var string
     */
    protected $pem_format;

    /**
     * @var RSA
     */
    protected $rsa_imp;

    /**
     * @var BigInteger
     */
    protected $n;

    /**
     * @var string
     */
    protected $password;

    /**
     * @return null|string
     */
    public function getPassword():?string{
        return $this->password;
    }

    /**
     * @return bool
     */
    public function hasPassword():bool{
        return !empty($this->password);
    }

    /**
     * @param string $pem_format
     * @param string $password
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format, $password = null){

        $this->pem_format = $pem_format;
        $this->rsa_imp    = new RSA();

        if(!empty($password)) {
            $this->password = trim($password);
            $this->rsa_imp->setPassword($this->password);
        }

        $res = $this->rsa_imp->loadKey($this->pem_format, RSA::PRIVATE_FORMAT_PKCS1);

        if(!$res) throw new RSABadPEMFormat(sprintf('pem %s',$pem_format ));

        $this->n = $this->rsa_imp->modulus;
    }

    /**
     * Returns The "n" (modulus)
     * @return BigInteger
     */
    public function getModulus()
    {
        return  $this->n;
    }

}