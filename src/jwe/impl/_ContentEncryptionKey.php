<?php namespace jwe\impl;
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
use security\Key;
use utils\ByteUtil;
/**
 * Class _ContentEncryptionKey
 * @package jwe\impl
 * @internal
 */
final class _ContentEncryptionKey implements Key {

    /**
     * @var string
     */
    private $alg;

    /**
     * @var string
     */
    private $value;

    /**
     * @var string
     */
    private $format;

    /**
     * @param string $alg
     * @param string $format
     * @param string $value
     */
    public function __construct($alg, $format, $value){
        $this->alg    = $alg;
        $this->format = $format;
        $this->value  = $value;
    }

    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->alg;
    }

    /**
     * @return string
     */
    public function getEncoded()
    {
        return $this->value;
    }

    /**
     * @return string
     */
    public function getFormat()
    {
       return $this->format;
    }

    /**
     * @return int
     */
    public function getBitLength()
    {
       return ByteUtil::bitLength(strlen($this->value));
    }

    /**
     * @return string
     */
    public function getStrippedEncoded(): string
    {
       return $this->getEncoded();
    }
}