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

namespace utils\json_types;


use utils\Base64UrlRepresentation;

/**
 * Class Base64urlUInt
 * @package utils\json_types
 */
class Base64urlUInt extends JsonValue {

    public function toBigInt(){
        $b64 = new Base64UrlRepresentation();
        $hex = bin2hex($b64->decode($this->value));
        return new \Math_BigInteger('0x'.$hex, 16);
    }

}