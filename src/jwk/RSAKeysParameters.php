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
 * Class RSAKeysParameters
 * @package jwk
 *
 * https://tools.ietf.org/html/rfc7518#section-6.3
 */
abstract class RSAKeysParameters {

    /**
     * The "n" (modulus) parameter contains the modulus value for the RSA
     * public key.  It is represented as a Base64urlUInt-encoded value.
     */
    const Modulus = 'n';

    /**
     * The "e" (exponent) parameter contains the exponent value for the RSA
     * public key.  It is represented as a Base64urlUInt-encoded value.
     */
    const Exponent = 'e';

    public static $public_key_params = array ( self::Modulus, self::Exponent);

    /**
     * The "d" (private exponent) parameter contains the private exponent
     * value for the RSA private key.  It is represented as a Base64urlUInt-
     * encoded value.
     */
    const PrivateExponent = 'd';

    /**
     * The "p" (first prime factor) parameter contains the first prime
     * factor.  It is represented as a Base64urlUInt-encoded value.
     */
    const FirstPrimeFactor = 'p';

    /**
     * The "q" (second prime factor) parameter contains the second prime
     * factor.  It is represented as a Base64urlUInt-encoded value.
     */
    const SecondPrimeFactor = 'q';

    /**
     * The "dp" (first factor CRT exponent) parameter contains the Chinese
     * Remainder Theorem (CRT) exponent of the first factor.  It is
     * represented as a Base64urlUInt-encoded value.
     */
    const FirstFactorCRTExponent = 'dp';

    /**
     * The "dq" (second factor CRT exponent) parameter contains the CRT
     * exponent of the second factor.  It is represented as a Base64urlUInt-
     * encoded value.
     */
    const SecondFactorCRTExponent = 'dq';

    /**
     * The "qi" (first CRT coefficient) parameter contains the CRT
     * coefficient of the second factor.  It is represented as a
     * Base64urlUInt-encoded value.
     */
    const FirstCRTCoefficient = 'qi';



    public static $producers_private_key_params = array (
        self::FirstPrimeFactor,
        self::SecondPrimeFactor,
        self::FirstFactorCRTExponent,
        self::SecondFactorCRTExponent,
    );

    public static $valid_algorithms_values = array(
        JSONWebSignatureAndEncryptionAlgorithms::RS256,
        JSONWebSignatureAndEncryptionAlgorithms::RS384,
        JSONWebSignatureAndEncryptionAlgorithms::RS512,
        JSONWebSignatureAndEncryptionAlgorithms::PS256,
        JSONWebSignatureAndEncryptionAlgorithms::PS384,
        JSONWebSignatureAndEncryptionAlgorithms::PS512,
        JSONWebSignatureAndEncryptionAlgorithms::RSA1_5,
        JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP,
        JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP_256,
    );
}