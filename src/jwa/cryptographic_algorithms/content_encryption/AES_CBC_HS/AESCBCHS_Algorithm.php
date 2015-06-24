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

namespace jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS;

use jwa\cryptographic_algorithms\content_encryption\ContentEncryptionAlgorithm;

/**
 * Class AESCBCHS_Algorithm
 * @package jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS
 */
abstract class AESCBCHS_Algorithm implements ContentEncryptionAlgorithm {

    /**
     * @var \Crypt_AES()
     */
    protected $aes;

    public function __construct()
    {
        $this->aes = new \Crypt_AES();
        $this->aes->Crypt_Base(CRYPT_AES_MODE_CBC);
    }

    /**
     * @return string
     */
    public function getKeyType()
    {
        return 'CEK';
    }

    /**
     * Encrypt data.
     *
     * @param string $data The data to encrypt
     * @param string $cek The content encryption key
     * @param string $iv The Initialization Vector
     * @param string|null $aad Additional Additional Authenticated Data
     * @param string $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string $tag Tag
     *
     * @return string The encrypted data
     */
    public function encryptContent($data, $cek, $iv, $aad, $encoded_protected_header, &$tag)
    {
        $k = substr($cek, strlen($cek) / 2);

        $this->aes->setKey($k);
        $this->aes->setIV($iv);

        $cyphertext = $this->aes->encrypt($data);
        $tag        = $this->calculateAuthenticationTag($cyphertext, $cek, $iv, $aad, $encoded_protected_header);

        return $cyphertext;
    }


    /**
     * @param $encrypted_data
     * @param $cek
     * @param $iv
     * @param string $encoded_header
     *
     * @return string
     */
    protected function calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header)
    {
        $calculated_aad = $encoded_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }
        $mac_key          = substr($cek, 0, strlen($cek) / 2);
        $auth_data_length = strlen($encoded_header);

        $secured_input = implode('', array(
            $calculated_aad,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8), // str_pad(dechex($auth_data_length), 4, "0", STR_PAD_LEFT)
        ));
        $hash = hash_hmac($this->getHashingAlgorithm(), $secured_input, $mac_key, true);

        return substr($hash, 0, strlen($hash) / 2);
    }

    /**
     * @param string      $authentication_tag
     * @param string      $encoded_header
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param string|null $aad
     */
    protected function checkAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header, $authentication_tag)
    {
        return $authentication_tag === $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header);
    }

    /**
     * Decrypt data.
     *
     * @param string $data The data to decrypt
     * @param string $cek The content encryption key
     * @param string $iv The Initialization Vector
     * @param string|null $aad Additional Additional Authenticated Data
     * @param string $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string $tag Tag
     *
     * @return string
     */
    public function decryptContent($data, $cek, $iv, $aad, $encoded_protected_header, $tag)
    {
        $this->checkAuthenticationTag($data, $cek, $iv, $aad, $encoded_protected_header, $tag);
        $k = substr($cek, strlen($cek) / 2);

        $this->aes->setKey($k);
        $this->aes->setIV($iv);

        return $this->aes->decrypt($data);
    }

    /**
     * @return int|null
     */
    public function getIVSize()
    {
       return $this->getMinKeyLen();
    }

    /**
     * @return int
     */
    public function getCEKSize()
    {
        return $this->getMinKeyLen();
    }
}