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

namespace jwk\utils\aes;


use jwk\utils\PrivateKey;
use utils\ByteUtil;

/**
 * Class AesKey
 * @package jwk\utils\aes
 */
final class AesKey implements PrivateKey {

    /**
     * @param string $secret
     */
    public function __construct($secret){
        $this->secret = $secret;
    }

    private $secret = null;
    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return 'AES';
    }

    /**
     * @return string
     */
    public function getEncoded()
    {
       return $this->secret;
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return 'RAW';
    }

    /**
     * @return int
     */
    public function getBitLength()
    {
        return ByteUtil::bitLength(strlen($this->secret));
    }
}