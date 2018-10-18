<?php namespace utils\json_types;
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
use phpseclib\Math\BigInteger;
/**
 * Class Base64urlUInt
 * @package utils\json_types
 */
class Base64urlUInt extends JsonValue {

    /**
     * @return BigInteger
     */
    public function toBigInt(){
        $b64 = new Base64UrlRepresentation();
        $hex = bin2hex($b64->decode($this->value));
        return new BigInteger('0x'.$hex, 16);
    }

    /**
     * @param BigInteger $big_int
     * @return Base64urlUInt
     */
    public static function fromBigInt(BigInteger $big_int){
        $b64 = new Base64UrlRepresentation();
        $input = $big_int->toBytes();
        return new Base64urlUInt($b64->encode($input));
    }
}