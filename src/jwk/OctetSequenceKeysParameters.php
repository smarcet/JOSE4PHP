<?php namespace jwk;
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
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
/**
 * Class OctetSequenceKeysParameters
 * @package jwk
 *
 * https://tools.ietf.org/html/rfc7518#section-6.4
 */
abstract class OctetSequenceKeysParameters
{

    /**
     * The "k" (key value) parameter contains the value of the symmetric (or
     * other single-valued) key.  It is represented as the base64url
     * encoding of the octet sequence containing the key value.
     */
    const Key = 'k';

    public static $valid_algorithms_values = [
        JSONWebSignatureAndEncryptionAlgorithms::HS256,
        JSONWebSignatureAndEncryptionAlgorithms::HS384,
        JSONWebSignatureAndEncryptionAlgorithms::HS512,
        JSONWebSignatureAndEncryptionAlgorithms::Dir,
        JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256,
        JSONWebSignatureAndEncryptionAlgorithms::A192CBC_HS384,
        JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512,
    ];
}