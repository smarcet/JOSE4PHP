<?php namespace jwt\utils;
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
use jwt\IJOSEHeader;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;
use utils\json_types\JsonValue;
/**
 * Class JOSEHeaderFactory
 * @package jwt\utils
 */
class JOSEHeaderFactory {

    static protected function getProductClass(){
        return  '\jwt\impl\JOSEHeader';
    }

    /**
     * @param array $raw_headers
     * @return object
     * @throws \ReflectionException
     */
    public static function build(array $raw_headers)
    {

        $args = [];

        foreach(RegisteredJOSEHeaderNames::$registered_basic_headers_set as $header_name){
            $value = isset($raw_headers[$header_name]) ? $raw_headers[$header_name] : null;
            $type  = @RegisteredJOSEHeaderNames::$registered_basic_headers_set_types[$header_name];
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