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
use security\rsa\exceptions\RSABadPEMFormat;
use phpseclib3\Math\BigInteger;
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
     * @var BigInteger
     */
    protected $n;

    /**
     * @var string
     */
    protected $password;

    protected $key;

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

        if(!empty($password)) {
            $this->password = trim($password);
        }

        try {
            $loaded_key = PublicKeyLoader::load($this->pem_format, $this->password ?? false);
            $this->key = new CustomAsymmetricKey($loaded_key);
        } catch (\Exception $e) {
            throw new RSABadPEMFormat(sprintf('pem %s', $pem_format));
        }
    }

    /**
     * Returns The "n" (modulus)
     * @return BigInteger
     */
    public function getModulus()
    {
        return  $this->key->getModulus();
    }

}