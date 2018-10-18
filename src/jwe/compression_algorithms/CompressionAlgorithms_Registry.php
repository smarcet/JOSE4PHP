<?php namespace jwe\compression_algorithms;
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
use jwe\compression_algorithms\impl\Deflate;
use jwe\compression_algorithms\impl\ZLib;
use jwe\compression_algorithms\impl\GZip;
/**
 * Class CompressionAlgorithms_Registry
 * @package jwe\compression_algorithms
 */
final class CompressionAlgorithms_Registry {

    /**
     * @var CompressionAlgorithms_Registry
     */
    private static $instance;

    private $algorithms = [];

    private function __construct(){

        $this->algorithms[CompressionAlgorithmsNames::Deflate] = new Deflate;
        $this->algorithms[CompressionAlgorithmsNames::GZip]    = new GZip;
        $this->algorithms[CompressionAlgorithmsNames::ZLib]    = new ZLib;

    }

    private function __clone(){}

    /**
     * @return CompressionAlgorithms_Registry
     */
    public static function getInstance(){
        if(!is_object(self::$instance)){
            self::$instance = new CompressionAlgorithms_Registry();
        }
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return bool
     */
    public function isSupported($alg){
        return array_key_exists($alg, $this->algorithms);
    }

    /**
     * @param $alg
     * @return null|CompressionAlgorithm
     */
    public function get($alg){
        if(!$this->isSupported($alg)) return null;
        return $this->algorithms[$alg];
    }
}