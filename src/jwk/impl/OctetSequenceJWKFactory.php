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

use jwk\IJWKSpecification;
use jwk\utils\aes\AesKey;
use utils\ByteUtil;
use \jwk\IJWK;
/**
 * Class OctetSequenceJWKFactory
 * @package jwk\impl
 */
final class OctetSequenceJWKFactory {

    /**
     * @param IJWKSpecification $spec
     * @return IJWK
     */
    static public function build(IJWKSpecification $spec){
        $bytes = ByteUtil::randomBytes($spec->getKeyLenInBits());
        return OctetSequenceJWK::fromSecret(new AesKey($bytes), $spec->getAlg(), $spec->getUse());
    }

}