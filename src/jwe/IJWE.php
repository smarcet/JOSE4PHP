<?php namespace jwe;
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
use jwa\cryptographic_algorithms\exceptions\InvalidAuthenticationTagException;
use jwe\exceptions\JWEInvalidCompactFormatException;
use jwe\exceptions\JWEInvalidRecipientKeyException;
use jwe\exceptions\JWEUnsupportedContentEncryptionAlgorithmException;
use jwe\exceptions\JWEUnsupportedKeyManagementAlgorithmException;
use jwk\IJWK;
use jws\IJWSPayloadSpec;
use jwt\IBasicJWT;
/**
 * Interface IJWE
 * @package jwe
 */
interface IJWE extends IBasicJWT {

    /**
     * @param IJWSPayloadSpec $payload
     * @return $this
     */
    public function setPayload(IJWSPayloadSpec $payload);

    /**
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     * @return string
     */
    public function toCompactSerialization();

    /**
     * @return string
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     * @throws InvalidAuthenticationTagException
     */
    public function getPlainText();

    /**
     * @param IJWK $recipient_key
     * @return $this
     */
    public function setRecipientKey(IJWK $recipient_key);


    /**
     * @return IJWEJOSEHeader
     */
    public function getJOSEHeader();

    // factory methods

    /**
     * @param string $compact_serialization
     * @return IJWE
     * @throws JWEInvalidCompactFormatException
     */
    public static function fromCompactSerialization($compact_serialization);

    /**
     * @param IJWEJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     * @return IJWE
     */
    public static function fromHeaderAndPayload(IJWEJOSEHeader $header, IJWSPayloadSpec $payload);

}