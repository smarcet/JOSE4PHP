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

use jwa\cryptographic_algorithms\ContentEncryptionAlgorithms_Registry;
use jwa\cryptographic_algorithms\KeyManagementAlgorithms_Registry;
use jwe\exceptions\JWEInvalidCompactFormatException;
use jwe\exceptions\JWEInvalidRecipientKeyException;
use jwe\exceptions\JWEUnsupportedContentEncryptionAlgorithmException;
use jwe\exceptions\JWEUnsupportedKeyManagementAlgorithmException;
use jwe\IJWEJOSEHeader;
use jwe\IJWE;
use jwe\KeyManagementModeValues;
use jwk\IJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jws\IJWSPayloadSpec;
use jws\payloads\JWSPayloadFactory;
use jwt\utils\JOSEHeaderSerializer;
use security\Key;
use utils\ByteUtil;

/**
 * Class JWE
 * @package jwe\impl
 * @access private
 */
final class JWE
    implements IJWE, IJWESnapshot
{

    /**
     * @var IJWK
     */
    private $jwk = null;

    /**
     * @var IJWSPayloadSpec
     */
    private $payload = null;

    /**
     * @var IJWEJOSEHeader
     */
    private $header;

    /**
     * @var Key
     */
    private $cek = null;

    private $tag = null;

    private $cipher_text = null;

    private $iv;

    private $enc_cek = null;

    private $should_decrypt = false;

    /**
     * @param IJWEJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     */
    protected function __construct(IJWEJOSEHeader $header, IJWSPayloadSpec $payload = null)
    {
        $this->header = $header;
        if(!is_null($payload))
            $this->setPayload($payload);
    }

    /**
     * @param IJWK $recipient_key
     * @return $this
     */
    public function setRecipientKey(IJWK $recipient_key)
    {
        $this->jwk = $recipient_key;
        return $this;
    }

    /**
     * @param IJWSPayloadSpec $payload
     * @return $this
     */
    public function setPayload(IJWSPayloadSpec $payload)
    {
        $this->payload = $payload;
        return $this;
    }

    private function getKeyManagementMode()
    {
        return KeyManagementModeValues::KeyEncryption;
    }

    /**
     * @return $this
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     */
    public function encrypt()
    {

        if (is_null($this->jwk))
            throw new JWEInvalidRecipientKeyException;

        $recipient_public_key = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::EncryptContent);

        $key_management_mode = $this->getKeyManagementMode();

        $key_management_algorithm = KeyManagementAlgorithms_Registry::getInstance()->get($this->header->getAlgorithm()->getString());

        if (is_null($key_management_algorithm)) throw new JWEUnsupportedKeyManagementAlgorithmException(sprintf('alg %s', $this->header->getAlgorithm()->getString()));

        $content_encryption_algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get($this->header->getEncryptionAlgorithm()->getString());

        if (is_null($content_encryption_algorithm)) throw new JWEUnsupportedContentEncryptionAlgorithmException(sprintf('enc %s', $this->header->getEncryptionAlgorithm()->getString()));

        $this->cek = ContentEncryptionKeyFactory::build($recipient_public_key, $key_management_mode, $key_management_algorithm);

        $this->enc_cek = $key_management_algorithm->encrypt($recipient_public_key, $this->cek->getEncoded());

        if (!is_null($iv_size = $content_encryption_algorithm->getIVSize())) {
            $this->iv = $this->createIV($iv_size);
        }
        // We encrypt the payload and get the tag
        $jwt_shared_protected_header = JOSEHeaderSerializer::serialize($this->header);

        $this->cipher_text = $content_encryption_algorithm->encryptContent($this->payload->getRaw(), $this->cek->getEncoded(), $this->iv, null, $jwt_shared_protected_header, $this->tag);

        return $this;
    }

    /**
     * @param int $size
     * @return String
     */
    protected function createIV($size)
    {
        return ByteUtil::randomBytes($size / 8);
    }

    /**
     * @return string
     */
    public function toCompactSerialization()
    {
        return JWESerializer::serialize($this->encrypt());
    }

    /**
     * @return string
     */
    public function getPlainText()
    {
        if ($this->should_decrypt) {
            $this->decrypt();
        }

        if (is_null($this->payload)) $this->payload = JWSPayloadFactory::build('');

        return $this->payload->getRaw();
    }

    /**
     * @return IJWEJOSEHeader
     */
    public function getJOSEHeader()
    {
        return $this->header;
    }

    /**
     * @param IJWEJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     * @return IJWE
     */
    public static function fromHeaderAndPayload(IJWEJOSEHeader $header, IJWSPayloadSpec $payload)
    {
        return new JWE($header, $payload);
    }

    /**
     * @param string $compact_serialization
     * @return IJWE
     * @throws JWEInvalidCompactFormatException
     * @access private
     */
    public static function fromCompactSerialization($compact_serialization)
    {

        list($header, $enc_cek, $iv, $cipher_text, $tag) = JWESerializer::deserialize($compact_serialization);
        $jwe     = new JWE($header);
        $jwe->iv = $iv;
        $jwe->tag = $tag;
        $jwe->enc_cek = $enc_cek;
        $jwe->cipher_text = $cipher_text;
        $jwe->should_decrypt = true;
        return $jwe;
    }

    /**
     * @return $this
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     */
    public function decrypt()
    {
        if (is_null($this->jwk))
            throw new JWEInvalidRecipientKeyException();

        if (!$this->should_decrypt) return $this;

        $recipient_private_key = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::DecryptContentAndValidateDecryption);

        $key_management_algorithm = KeyManagementAlgorithms_Registry::getInstance()->get($this->header->getAlgorithm()->getString());

        if (is_null($key_management_algorithm)) throw new JWEUnsupportedKeyManagementAlgorithmException(sprintf('alg %s', $this->header->getAlgorithm()->getString()));

        $content_encryption_algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get($this->header->getEncryptionAlgorithm()->getString());

        if (is_null($content_encryption_algorithm)) throw new JWEUnsupportedContentEncryptionAlgorithmException(sprintf('enc %s', $this->header->getEncryptionAlgorithm()->getString()));

        $this->cek = $key_management_algorithm->decrypt($recipient_private_key, $this->enc_cek);

        // We encrypt the payload and get the tag
        $jwt_shared_protected_header = JOSEHeaderSerializer::serialize($this->header);

        $plain_text = $content_encryption_algorithm->decryptContent($this->cipher_text, $this->cek, $this->iv, null, $jwt_shared_protected_header, $this->tag);

        $this->setPayload(JWSPayloadFactory::build($plain_text));
        $this->should_decrypt = false;

        return $this;
    }

    /**
     * @return array
     */
    public function take()
    {

        return array(
            $this->header,
            $this->enc_cek,
            $this->iv,
            $this->cipher_text,
            $this->tag);
    }
}