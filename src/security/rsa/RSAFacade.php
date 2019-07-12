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
use security\KeyPair;
use security\rsa\exceptions\RSABadPEMFormat;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
/**
 * Class RSAFacade
 * @package security\rsa
 */
final class RSAFacade {

    /**
     * @var RSAFacade
     */
    private static $instance;

    /**
     * @var RSA
     */
    private $rsa_imp;

    private function __construct(){
        $this->rsa_imp = new RSA();
    }

    private function __clone(){}

    /**
     * @return RSAFacade
     */
    public static function getInstance(){
        if(!is_object(self::$instance)){
            self::$instance = new RSAFacade();
        }
        return self::$instance;
    }

    /**
     * @param $bits
     * @return KeyPair
     */
    public function buildKeyPair($bits){
        $this->rsa_imp->setPrivateKeyFormat(RSA::PRIVATE_FORMAT_PKCS1);
        $this->rsa_imp->setPublicKeyFormat(RSA::PUBLIC_FORMAT_PKCS1);

        $list = $this->rsa_imp->createKey($bits);
        return new KeyPair( new _RSAPublicKeyPEMFormat($list['publickey']), new _RSAPrivateKeyPEMFormat($list['privatekey']));
    }

    /**
     * @param BigInteger $n
     * @param BigInteger $e
     * @return RSAPublicKey
     */
    public function buildPublicKey(BigInteger $n, BigInteger $e){
        $public_key_pem = $this->rsa_imp->_convertPublicKey($n, $e);
        return new _RSAPublicKeyPEMFormat($public_key_pem);
    }

    /**
     * @param \Math_BigInteger $n
     * @param \Math_BigInteger $d
     * @return RSAPrivateKey
     */
    public function buildMinimalPrivateKey(\Math_BigInteger $n, \Math_BigInteger $d){
        $this->rsa_imp->modulus = $n;
        $this->rsa_imp->exponent = $d;
        $private_key_pem = $this->rsa_imp->_getPrivatePublicKey();
        return new _RSAPrivateKeyPEMFormat($private_key_pem);
    }

    /**
     * @param BigInteger $n
     * @param BigInteger $e
     * @param BigInteger $d
     * @param BigInteger $p
     * @param BigInteger $q
     * @param BigInteger $dp
     * @param BigInteger $dq
     * @param BigInteger $qi
     * @return RSAPrivateKey
     */
    public function buildPrivateKey(BigInteger $n,
                                    BigInteger $e,
                                    BigInteger $d,
                                    BigInteger $p,
                                    BigInteger $q,
                                    BigInteger $dp,
                                    BigInteger $dq,
                                    BigInteger $qi){

        $private_key_pem = $this->rsa_imp->_convertPrivateKey(
            $n,
            $e,
            $d,
            array($p, $q),
            array($dp, $dq),
            array($qi, $qi)
        );
        return new _RSAPrivateKeyPEMFormat($private_key_pem);
    }

    /**
     * @param string $private_key_pem
     * @param string $password
     * @return RSAPrivateKey
     * @throws RSABadPEMFormat
     */
    public function buildPrivateKeyFromPEM($private_key_pem, $password = null){
       return new _RSAPrivateKeyPEMFormat($private_key_pem, $password);
    }

    /**
     * @param string $public_key_pem
     * @return RSAPublicKey
     * @throws RSABadPEMFormat
     */
    public function buildPublicKeyFromPEM($public_key_pem){
        return new _RSAPublicKeyPEMFormat($public_key_pem);
    }

}