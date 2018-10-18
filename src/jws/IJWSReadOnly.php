<?php namespace jws;
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
use jwt\IJWT;
use utils\json_types\StringOrURI;
/**
 * Interface IJWSReadOnly
 * @package jws
 */
interface IJWSReadOnly extends IJWT {

    /**
     * https://tools.ietf.org/html/rfc7515#section-4.1.1
     *
     * The "alg" (algorithm) Header Parameter identifies the cryptographic
     * algorithm used to secure the JWS.  The JWS Signature value is not
     * valid if the "alg" value does not represent a supported algorithm or
     * if there is not a key for use with that algorithm associated with the
     * party that digitally signed or MACed the content.
     * @return StringOrURI
     */
    public function getSigningAlgorithm();

    /**
     * @return StringOrURI
     */
    public function getType();
}