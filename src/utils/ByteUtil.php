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

namespace utils;

/**
 * Class ByteUtil
 * @package utils
 */
final class ByteUtil {

    /**
     * @param int $byte_len
     * @return int
     */
    static public function bitLength($byte_len){
        return $byte_len * 8;
    }

    static public function randomBytes($bits_len){
        return crypt_random_string((int)($bits_len/8));
    }
}