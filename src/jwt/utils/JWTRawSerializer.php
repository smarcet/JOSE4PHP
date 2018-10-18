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
use utils\Base64UrlRepresentation;

/**
 * Class JWTRawSerializer
 * @package jwt\utils
 */
class JWTRawSerializer {

    /**
     * @param string $raw_input
     * @return string
     */
    public static function serialize($raw_input){
        $base64 = new Base64UrlRepresentation();
        return $base64->encode($raw_input);
    }

    /**
     * @param string $input
     * @return string
     */
    public static function deserialize($input){
        $base64 = new Base64UrlRepresentation();
        return $base64->decode($input);
    }
}