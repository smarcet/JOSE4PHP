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

namespace jws;


use jwa\JSONWebSignatureAndEncryptionAlgorithms;

/**
 * Class JWSupportedSigningAlgorithms
 * @package jws
 */
final class JWSupportedSigningAlgorithms {

    // HMAC with SHA-2 Functions
    // https://tools.ietf.org/html/rfc7518#section-3.2
    const HS256 = JSONWebSignatureAndEncryptionAlgorithms::HS256;
    const HS384 = JSONWebSignatureAndEncryptionAlgorithms::HS384;
    const HS512 = JSONWebSignatureAndEncryptionAlgorithms::HS512;
    // Digital Signature with RSASSA-PKCS1-v1_5
    // https://tools.ietf.org/html/rfc7518#section-3.3
    const RS256 = JSONWebSignatureAndEncryptionAlgorithms::RS256;
    const RS384 = JSONWebSignatureAndEncryptionAlgorithms::RS384;
    const RS512 = JSONWebSignatureAndEncryptionAlgorithms::RS512;
    // Digital Signature with RSASSA-PSS
    // https://tools.ietf.org/html/rfc7518#section-3.5
    const PS256 = JSONWebSignatureAndEncryptionAlgorithms::PS256;
    const PS384 = JSONWebSignatureAndEncryptionAlgorithms::PS384;
    const PS512 = JSONWebSignatureAndEncryptionAlgorithms::PS512;

    public static $algorithms = array(
        JSONWebSignatureAndEncryptionAlgorithms::HS256,
        JSONWebSignatureAndEncryptionAlgorithms::HS384,
        JSONWebSignatureAndEncryptionAlgorithms::HS512,
        JSONWebSignatureAndEncryptionAlgorithms::RS256,
        JSONWebSignatureAndEncryptionAlgorithms::RS384,
        JSONWebSignatureAndEncryptionAlgorithms::RS512,
        JSONWebSignatureAndEncryptionAlgorithms::PS256,
        JSONWebSignatureAndEncryptionAlgorithms::PS384,
        JSONWebSignatureAndEncryptionAlgorithms::PS512,
    );
}