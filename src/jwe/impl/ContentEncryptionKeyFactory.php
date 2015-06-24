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

namespace jwe\impl;

use jwa\cryptographic_algorithms\EncryptionAlgorithm;
use jwe\KeyManagementModeValues;
use security\Key;
use utils\ByteUtil;

/**
 * Class ContentEncryptionKeyFactory
 *
 * Creates the CEK
 *
 * @package jwe\impl
 */
final class ContentEncryptionKeyFactory
{

    /**
     * @param Key $management_key
     * @param $key_management_mode
     * @param EncryptionAlgorithm $alg
     * @return Key
     */
    static public function build(Key $management_key, $key_management_mode, EncryptionAlgorithm $alg)
    {

        $cek = null;

        switch ($key_management_mode) {
            case KeyManagementModeValues::KeyWrapping:
            case KeyManagementModeValues::KeyEncryption: {
                // calculate it
                $size = $alg->getMinKeyLen();
                $cek = new _ContentEncryptionKey($alg->getName(), 'RAW', ByteUtil::randomBytes($size / 8));
            }
            break;
            case KeyManagementModeValues::DirectEncryption: {
                $cek = $management_key;
            }
            break;
        }
        return $cek;
    }
}