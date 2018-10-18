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



/**
 * Class JSONWebKeyParameters
 * @package jwk
 */
abstract class JSONWebKeyParameters {

    /**
     * @mandatory
     *
     *  The "kty" (key type) parameter identifies the cryptographic algorithm
     * family used with the key, such as "RSA" or "EC".  "kty" values should
     * either be registered in the IANA "JSON Web Key Types" registry
     * established by [JWA] or be a value that contains a Collision-
     * Resistant Name.  The "kty" value is a case-sensitive string.  This
     * member MUST be present in a JWK.
     * A list of defined "kty" values can be found in the IANA "JSON Web Key
     * Types" registry established by [JWA]; the initial contents of this
     * registry are the values defined in Section 6.1 of [JWA].
     */
    const KeyType = "kty";


    /**
     * @optional
     *
     * The "use" (public key use) parameter identifies the intended use of
     * the public key.  The "use" parameter is employed to indicate whether
     * a public key is used for encrypting data or verifying the signature
     * on data.
     * Values defined by this specification are:
     * o  "sig" (signature)
     * o  "enc" (encryption)
     * Other values MAY be used.  The "use" value is a case-sensitive
     * string.  Use of the "use" member is OPTIONAL, unless the application
     * requires its presence.
     */
    const PublicKeyUse = "use";

    /**
     * @optional
     *
     * The "alg" (algorithm) parameter identifies the algorithm intended for
     * use with the key.  The values used should either be registered in the
     * IANA "JSON Web Signature and Encryption Algorithms" registry
     * established by [JWA] or be a value that contains a Collision-
     * Resistant Name.  The "alg" value is a case-sensitive ASCII string.
     * Use of this member is OPTIONAL.
     */
    const Algorithm = 'alg';


    /**
     * @optional
     *
     * The "kid" (key ID) parameter is used to match a specific key.  This
     * is used, for instance, to choose among a set of keys within a JWK Set
     * during key rollover.  The structure of the "kid" value is
     * unspecified.  When "kid" values are used within a JWK Set, different
     * keys within the JWK Set SHOULD use distinct "kid" values.  (One
     * example in which different keys might use the same "kid" value is if
     * they have different "kty" (key type) values but are considered to be
     * equivalent alternatives by the application using them.)  The "kid"
     * value is a case-sensitive string.  Use of this member is OPTIONAL.
     * When used with JWS or JWE, the "kid" value is used to match a JWS or
     * JWE "kid" Header Parameter value.
     */
    const KeyId = 'kid';


    /**
     * The "key_ops" (key operations) parameter identifies the operation(s)
     * for which the key is intended to be used.  The "key_ops" parameter is
     * intended for use cases in which public, private, or symmetric keys
     * may be present.
     */
    const KeyOperations = 'key_ops';

}