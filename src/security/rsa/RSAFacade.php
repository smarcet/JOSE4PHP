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

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use security\KeyPair;
use security\rsa\exceptions\RSABadPEMFormat;
use phpseclib3\Math\BigInteger;

/**
 * Class RSAFacade
 * @package security\rsa
 */
final class RSAFacade {

    /**
     * @var RSAFacade
     */
    private static $instance;

    private function __construct(){
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
        $private = RSA::createKey($bits);
        $public = $private->getPublicKey();

        $private_pem = $private->toString('PKCS1');
        $public_pem = $public->toString('PKCS1');

        return new KeyPair( new _RSAPublicKeyPEMFormat($public_pem), new _RSAPrivateKeyPEMFormat($private_pem));
    }

    /**
     * @param BigInteger $n
     * @param BigInteger $e
     * @return RSAPublicKey
     */
    public function buildPublicKey(BigInteger $n, BigInteger $e){


        $key = PublicKeyLoader::load([
            'n' => $n,
            'e' => $e
        ]);

        $pem = $key->toString('pkcs1');
        return new _RSAPublicKeyPEMFormat($pem);
    }

    /**
     * @param BigInteger $n
     * @param BigInteger $e
     * @param BigInteger $d
     * @return RSAPrivateKey
     */
    public function buildMinimalPrivateKey(BigInteger $n, BigInteger $e, BigInteger $d){
        $key = PublicKeyLoader::load([
            'n' => $n,
            'e' => $e,
            'd' => $d
        ]);
        $private_key_pem = $key->toString('PKCS1');
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

        $key = PublicKeyLoader::load([
            'n'  => $n,
            'e'  => $e,
            'd'  => $d,
            'p'  => $p,
            'q'  => $q,
            'dp' => $dp,
            'dq' => $dq,
            'inverseq' => $qi
        ]);
        $private_key_pem = $key->toString('PKCS1');
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