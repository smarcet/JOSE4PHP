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
use phpseclib\Math\BigInteger;
use phpseclib\Crypt\RSA;
/**
 * Class _RSAPrivateKeyPEMFornat
 * @package security\rsa
 */
final class _RSAPrivateKeyPEMFormat
    extends _RSAPublicKeyPEMFormat
    implements RSAPrivateKey {

    /**
     * @var BigInteger
     */
    private $d;

    /**
     * @param $pem_format
     * @param string $password
     * @throws RSABadPEMFormat
     */
    public function __construct($pem_format, $password = null){

        parent::__construct($pem_format, $password);
        $this->d = $this->rsa_imp->exponent;
        if($this->d->toString() === $this->e->toString())
            throw new RSABadPEMFormat(sprintf('pem %s is a public key!', $pem_format));
    }

    /**
     * The "d" (private exponent)
     *
     * @return BigInteger
     */
    public function getPrivateExponent()
    {
       return $this->d;
    }

    /**
     * @return string
     */
    public function getEncoded()
    {
        return $this->rsa_imp->getPrivateKey(RSA::PRIVATE_FORMAT_PKCS1);
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return 'PKCS1';
    }

    /**
     * @return string
     */
    public function getStrippedEncoded(): string
    {
        $pem = preg_replace('/\-+BEGIN RSA PRIVATE KEY\-+/','',$this->getEncoded());
        $pem = preg_replace('/\-+END RSA PRIVATE KEY\-+/','',$pem);
        $pem = str_replace( array("\n","\r","\t"), '', trim($pem));
        return $pem;
    }

}