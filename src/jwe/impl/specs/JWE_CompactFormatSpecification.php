<?php namespace jwe\impl\specs;
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
use jwe\IJWE_CompactFormatSpecification;
/**
 * Class JWE_CompactFormatSpecification
 * @package jwe\impl\specs
 */
final class JWE_CompactFormatSpecification implements IJWE_CompactFormatSpecification {

    /**
     * @var string
     */
    private $compact_format;

    /**
     * @param string $compact_format
     */
    public function __construct($compact_format){
        $this->compact_format = $compact_format;
    }

    /**
     * @return string
     */
    public function getCompactFormat()
    {
        return $this->compact_format;
    }
}