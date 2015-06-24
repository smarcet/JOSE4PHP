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
 * Class _RSAPrivateKeyPEMFornat
 * @package security\rsa
 */
final class _RSAPrivateKeyPEMFornat
    extends _RSAPublicKeyPEMFornat
    implements RSAPrivateKey {

    /**
     * @var \Math_BigInteger
     */
    private $d;

    /**
     * @param $pem_format
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format){

        parent::__construct($pem_format);
        $this->d = $this->rsa_imp->exponent;
        if($this->d->toString() === $this->e->toString())
            throw new RSABadPEMFormat(sprintf('pem %s is a public key!', $pem_format));
    }

    /**
     * The "d" (private exponent)
     *
     * @return \Math_BigInteger
     */
    public function getPrivateExponent()
    {
       return $this->d;
    }

}