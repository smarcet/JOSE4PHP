<?php namespace utils;
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
use phpseclib\Crypt\Random;
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

    /**
     * @param int $byte_len
     * @return String
     */
    static public function randomBytes($byte_len){
        return Random::string($byte_len);
    }

    /**
     * @param array $oct
     * @return string
     */
    static public function convertHalfWordArrayToBin(array $oct){
        $hex = '';
        foreach($oct as $b){
            $hex .= str_pad(dechex($b),2,'0',STR_PAD_LEFT);
        }
        return self::hex2bin($hex);
    }

    /**
     * @param int $nbr
     * @return string
     */
    static public function convert2UnsignedLongBE($nbr){
        $hex = str_pad(dechex($nbr),16,'0',STR_PAD_LEFT);
        return self::hex2bin($hex);
    }

    static public function hex2bin($hex_string){
        if ( function_exists( 'hex2bin' ) ){
            return hex2bin($hex_string);
        }
        return pack("H*" , $hex_string);
    }
}