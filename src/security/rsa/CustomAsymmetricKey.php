<?php namespace security\rsa;
/**
 * Copyright 2025 OpenStack Foundation
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
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\RSA;
use phpseclib\Crypt\RSA as RSA_OLD;

/**
 * @class CustomPrivateKey
 * this is a decorator in order to add getter fpr protected methods
 */
class CustomAsymmetricKey extends RSA
{

    protected $key;
    public function __construct(AsymmetricKey $key){
        parent::__construct();
        $this->key = $key;
    }
    public function getModulus(){
        return $this->key->modulus;
    }

    public function getPrivateExponent(){
        return $this->key->exponent;
    }

    public function getPublicExponent(){
        return $this->key->publicExponent;
    }

    public function toString($type = RSA_OLD::PRIVATE_FORMAT_PKCS8, array $options = [])
    {
        return $this->key->toString($type, $options);
    }
}