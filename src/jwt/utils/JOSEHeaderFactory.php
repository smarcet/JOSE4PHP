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

namespace jwt\utils;


use jwt\IJOSEHeader;
use jwt\RegisteredJOSEHeaderNames;

final class JOSEHeaderFactory {

    /**
     * @param array $raw_headers
     * @param string $header_type
     * @return IJOSEHeader
     */
    public static function build(array $raw_headers, $header_type){

        $args = array();

        foreach(RegisteredJOSEHeaderNames::$registered_basic_headers_set as $header_name){
            $value = isset($raw_headers[$header_name]) ? $raw_headers[$header_name] : null;
            $type  = RegisteredJOSEHeaderNames::$registered_basic_headers_set[$header_name];
            if(!is_null($value))
            {
                $class    = new ReflectionClass($type);
                $value    = $class->newInstanceArgs(array($value));
            }
            array_push($args, $value);
            unset($raw_headers[$header_name]);
        }


        $class         = new ReflectionClass('\jwt\impl\JOSEHeader');
        $basic_header = $class->newInstanceArgs($args);

        // unregistered headers

        foreach($raw_headers as $k => $v){
            $basic_header->addCustomHeader(new JOSEHeaderParam($k, new JsonValue($v)));
        }

        return $basic_header;
    }
}