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
use jwa\cryptographic_algorithms\content_encryption\ContentEncryptionAlgorithm;
use jwa\cryptographic_algorithms\EncryptionAlgorithm;
use jwe\KeyManagementModeValues;
use security\Key;
use utils\services\Utils_Registry;
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
     * @param ContentEncryptionAlgorithm $enc
     * @return Key
     * @throws \Exception
     */
    static public function build(Key $management_key, $key_management_mode, ContentEncryptionAlgorithm $enc)
    {

        $cek = null;

        switch ($key_management_mode) {
            /**
             * When Key Wrapping, Key Encryption, or Key Agreement with Key
             * Wrapping are employed, generate a random CEK value
             */
            case KeyManagementModeValues::KeyWrapping:
            case KeyManagementModeValues::KeyEncryption:
            case KeyManagementModeValues::KeyAgreementWithKeyWrapping:
            {
                // calculate it
                $generator = Utils_Registry::getInstance()->get(Utils_Registry::RandomNumberGeneratorService);
                /**
                 * The CEK MUST have a length equal to that required for the
                 * content encryption algorithm.
                 */
                $rnd       = $generator->invoke($enc->getMinKeyLen()/8);
                $cek       = new _ContentEncryptionKey($enc->getName(), 'RAW', $rnd);
            }
            break;
            case KeyManagementModeValues::DirectEncryption:
            {
                $cek = $management_key;
            }
            break;
            case KeyManagementModeValues::DirectKeyAgreement:
            {
                throw new \Exception('unsupported KKM!');
            }
            break;
            default:
            {
                throw new \Exception('unsupported KKM!');
            }
            break;
        }
        return $cek;
    }

    /**
     * @param string $value
     * @param EncryptionAlgorithm $alg
     * @return Key
     */
    static public function fromRaw($value, EncryptionAlgorithm $alg){
        return  new _ContentEncryptionKey($alg->getName(), 'RAW', $value);
    }
}