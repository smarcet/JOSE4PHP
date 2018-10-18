<?php namespace jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS;
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
use jwa\cryptographic_algorithms\exceptions\InvalidAuthenticationTagException;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyLengthAlgorithmException;
use utils\ByteUtil;
use phpseclib\Crypt\AES;
/**
 * Class AES_CBC_HMAC_SHA2_Algorithm
 * @package jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS
 *
 * https://tools.ietf.org/html/rfc7518#section-5.2.2
 */
abstract class AES_CBC_HMAC_SHA2_Algorithm implements ContentEncryptionAlgorithm
{

    /**
     * @var AES
     */
    protected $aes;

    public function __construct()
    {
        $this->aes = new AES(AES::MODE_CBC);
    }

    /**
     * @return string
     */
    public function getKeyType()
    {
        return 'CEK';
    }

    /**
     * https://tools.ietf.org/html/rfc7518#section-5.2.2.1
     * @param string $plain_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @return \string[]
     * @throws InvalidKeyLengthAlgorithmException
     */
    public function encrypt($plain_text, $key, $iv, $aad)
    {
        $key_len = strlen($key);

        if($this->getMinKeyLen() > ByteUtil::bitLength($key_len))
            throw new InvalidKeyLengthAlgorithmException;

        $enc_key_len = $key_len / 2;
        // ENC_KEY = final ENC_KEY_LEN octets of K
        $enc_key     = substr($key, $enc_key_len);

        $this->aes->setKey($enc_key);
        $this->aes->setIV($iv);

        $cypher_text = $this->aes->encrypt($plain_text);
        $tag         = $this->calculateAuthenticationTag($cypher_text, $key, $iv, $aad);

        return array($cypher_text, $tag);
    }

    /**
     * @param string $cypher_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @return string
     */
    protected function calculateAuthenticationTag($cypher_text, $key, $iv, $aad)
    {
        // first octets of key
        $t_len   = $mac_key_len = strlen($key) / 2;
        // MAC_KEY = initial MAC_KEY_LEN octets of K
        $mac_key = substr($key, 0, $mac_key_len);
            /**
         * The octet string AL is equal to the number of bits in the
         * Additional Authenticated Data ($aad) expressed as a 64-bit unsigned
         * big-endian integer
         */
        $al = ByteUtil::convert2UnsignedLongBE(strlen($aad) * 8);
        // M = MAC(MAC_KEY, A || IV || E || AL)
        $secured_input = implode('', array(
            $aad,
            $iv,
            $cypher_text,
            $al
        ));
        $m = hash_hmac($this->getHashingAlgorithm(), $secured_input, $mac_key, true);
        // T = initial T_LEN octets of M.
        return substr($m, 0, $t_len);
    }

    /**
     * @param string $cypher_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @param string $tag
     * @return bool
     */
    protected function checkAuthenticationTag($cypher_text, $key, $iv, $aad, $tag)
    {
        return $tag === $this->calculateAuthenticationTag($cypher_text, $key, $iv, $aad);
    }

    /**
     * https://tools.ietf.org/html/rfc7518#section-5.2.2.2
     *
     * @param string $cypher_text
     * @param string $key
     * @param string $iv
     * @param string $aad
     * @param string $tag
     * @return string
     * @throws InvalidAuthenticationTagException
     */
    public function decrypt($cypher_text, $key, $iv, $aad, $tag)
    {
        if(!$this->checkAuthenticationTag($cypher_text, $key, $iv, $aad, $tag))
            throw new InvalidAuthenticationTagException;

        $enc_key_len = strlen($key) / 2;
        // ENC_KEY = final ENC_KEY_LEN octets of K
        $enc_key = substr($key, $enc_key_len);

        $this->aes->setKey($enc_key);
        $this->aes->setIV($iv);

        return $this->aes->decrypt($cypher_text);
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