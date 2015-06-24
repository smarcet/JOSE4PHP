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
use jwe\IEncJOSEHeader;
use jwe\IJWE;
use jwe\KeyManagementModeValues;
use jwk\IJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jws\IJWSPayloadRawSpec;
use jwt\exceptions\InvalidJWTException;
use jwt\IJOSEHeader;
use jwt\IJWTClaimSet;
use jwt\impl\JWT;
use jwt\utils\JOSEHeaderAssembler;
use jwt\utils\JWTRawAssembler;
use security\Key;
use utils\ByteUtil;

/**
 * Class JWE
 * @package jwe\impl
 */
final class JWE
    extends JWT
    implements IJWE {

    /**
     * @var IJWK
     */
    private $jwk = null;

    /**
     * @var IJWSPayloadRawSpec
     */
    private $payload = null;

    /**
     * @var Key
     */
    private $cek = null;

    private $tag = null;

    private $cipher_text = null;

    private $iv;

    private $enc_cek = null;


    protected function __construct(IEncJOSEHeader $header, IJWSPayloadRawSpec $payload){

        parent::__construct($header);

        $this->setPayload($payload);
    }

    /**
     * @param IJWK $key
     * @return $this
     */
    public function setKey(IJWK $key)
    {
        $this->jwk = $key;
        return $this;
    }


    public function setPayload(IJWSPayloadRawSpec $payload)
    {
        $this->payload = $payload;
    }

    private function getKeyManagementMode(){
        return KeyManagementModeValues::KeyEncryption;
    }

    /**
     * @return $this
     */
    public function encrypt(){

        $recipient_public_key         = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::EncryptContent);

        $key_management_mode          = $this->getKeyManagementMode();

        $key_management_algorithm     = KeyManagementAlgorithms_Registry::getInstance()->get($this->header->getAlgorithm()->getString());

        $content_encryption_algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get($this->header->getEncryptionAlgorithm()->getString());

        $this->cek                    = ContentEncryptionKeyFactory::build($recipient_public_key, $key_management_mode, $key_management_algorithm);

        $this->enc_cek                = $key_management_algorithm->encrypt($recipient_public_key, $this->cek->getEncoded() );

        if (!is_null($iv_size = $content_encryption_algorithm->getIVSize())) {
            $this->iv = $this->createIV($iv_size);
        }
        // We encrypt the payload and get the tag
        $jwt_shared_protected_header  = JOSEHeaderAssembler::serialize($this->header);
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
    public function serialize()
    {
        return $this->encrypt()->_serialize();
    }

    /**
     * @return string
     */
    private function _serialize(){

        $header      = JOSEHeaderAssembler::serialize($this->header);
        $enc_cek     = JWTRawAssembler::serialize($this->enc_cek);
        $iv          = JWTRawAssembler::serialize($this->iv);
        $cipher_text = JWTRawAssembler::serialize($this->cipher_text);
        $tag         = JWTRawAssembler::serialize($this->tag);

        return sprintf('%s.%s.%s.%s.%s', $header, $enc_cek, $iv, $cipher_text, $tag);
    }


    /**
     * @return string
     */
    public function getPlainText()
    {
        // TODO: Implement getPlainText() method.
    }

    /**
     * @return IJOSEHeader
     */
    public function getJOSEHeader()
    {
        // TODO: Implement getJOSEHeader() method.
    }

    /**
     * @return IJWTClaimSet
     */
    public function getClaimSet()
    {
        // TODO: Implement getClaimSet() method.
    }

    /**
     * @return string|null
     */
    public function getSignature()
    {
        // TODO: Implement getSignature() method.
    }

    /**
     * @param string $input
     * @return array
     * @throws InvalidJWTException
     */
    public static function unSerialize($input)
    {
        // TODO: Implement unSerialize() method.
    }


    /**
     * @param IEncJOSEHeader $header
     * @param IJWSPayloadRawSpec $payload
     * @return IJWE
     */
    public static function fromHeaderAndPayload(IEncJOSEHeader $header, IJWSPayloadRawSpec $payload){
        return new JWE($header, $payload);
    }

    /**
     * @param string $compact_serialization
     * @return $this
     */
    public static function fromCompactSerialization($compact_serialization){

    }
}