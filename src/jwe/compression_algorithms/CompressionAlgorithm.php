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

/**
 * class CompressionAlgorithm
 * @package jwe\compression_algorithms
 */
abstract class CompressionAlgorithm {
    protected $compression_level = -1;

    public function setCompressionLevel($level)
    {
        if (!is_numeric($level) || $level < -1 || $level > 9) {
            throw new \InvalidArgumentException('The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        }

        return $this;
    }

    public function getCompressionLevel()
    {
        return $this->compression_level;
    }
    
    /**
     * @return string
     */
    abstract public function getName();

    /**
     * @param string $data
     * @return string
     */
    abstract public function compress($data);

    /**
     * @param string $data
     * @return string
     */
    abstract public function uncompress($data);
}