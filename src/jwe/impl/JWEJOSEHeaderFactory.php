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
use jwe\IJWEJOSEHeader;
use jwe\RegisteredJWEJOSEHeaderNames;
use jwt\JOSEHeaderParam;
use utils\json_types\JsonValue;
/**
 * Class JWEJOSEHeaderFactory
 * @package jwe\impl
 */
final class JWEJOSEHeaderFactory {

    static protected function getProductClass(){
        return  '\jwe\impl\JWEJOSEHeader';
    }

    /**
     * @param array $raw_headers
     * @return IJWEJOSEHeader
     * @throws \ReflectionException
     */
    public static function build(array $raw_headers){

        $args = array();

        foreach(RegisteredJWEJOSEHeaderNames::$registered_basic_headers_set as $header_name){
            $value = isset($raw_headers[$header_name]) ? $raw_headers[$header_name] : null;
            $type  = @RegisteredJWEJOSEHeaderNames::$registered_basic_headers_set_types[$header_name];
            if(!is_null($value))
            {
                if(is_null($type)) continue;
                $class    = new \ReflectionClass($type);
                $value    = $class->newInstanceArgs(array($value));
            }
            array_push($args, $value);
            unset($raw_headers[$header_name]);
        }


        $class        = new \ReflectionClass(self::getProductClass());
        $basic_header = $class->newInstanceArgs($args);

        // unregistered headers

        foreach($raw_headers as $k => $v){
            $basic_header->addHeader(new JOSEHeaderParam($k, new JsonValue($v)));
        }

        return $basic_header;
    }
}