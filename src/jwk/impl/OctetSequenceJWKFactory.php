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

namespace jwk\impl;


use jwk\JSONWebKeyPublicKeyUseValues;
use jwk\utils\aes\AesKey;
use utils\ByteUtil;
use \jwk\IJWK;
/**
 * Class OctetSequenceJWKFactory
 * @package jwk\impl
 */
final class OctetSequenceJWKFactory {

    /**
     * @param int $key_length_in_bits
     * @param string $alg
     * @return IJWK
     */
    static public function build($key_length_in_bits, $alg, $use = JSONWebKeyPublicKeyUseValues::Signature){
        $bytes = ByteUtil::randomBytes($key_length_in_bits);
        return OctetSequenceJWK::fromSecret(new AesKey($bytes), $alg , $use);
    }
}