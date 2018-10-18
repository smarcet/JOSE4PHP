<?php namespace jwt;
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
use utils\json_types\IJsonObject;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;
/**
 * Interface IReadOnlyJOSEHeader
 * @package jwt
 */
interface IReadOnlyJOSEHeader extends IJsonObject, \ArrayAccess {

    /**
     * @mandatory
     * https://tools.ietf.org/html/rfc7515#section-4.1.1
     *
     * The "alg" (algorithm) Header Parameter identifies the cryptographic
     * algorithm used to secure the JWS.  The JWS Signature value is not
     * valid if the "alg" value does not represent a supported algorithm or
     * if there is not a key for use with that algorithm associated with the
     * party that digitally signed or MACed the content.
     *
     * @return StringOrURI
     */
    public function getAlgorithm();

    /**
     * @mandatory
     *
     * https://tools.ietf.org/html/rfc7515#section-4.1.4
     *
     * the "kid" (key ID) Header Parameter is a hint indicating which key
     * was used to secure the JWS. This parameter allows originators to
     * explicitly signal a change of key to recipients.
     *
     * @return JsonValue
     */
    public function getKeyID();

    /**
     * https://tools.ietf.org/html/rfc7515#section-4.1.10
     *
     * @optional
     *
     * The "cty" (content type) Header Parameter is used by JWS applications
     * to declare the media type [IANA.MediaTypes] of the secured content
     * (the payload)
     * @return StringOrURI
     */
    public function getContentType();

    /**
     * https://tools.ietf.org/html/rfc7515#section-4.1.9
     *
     * @optional
     *
     * The "typ" (type) Header Parameter is used by JWS applications to
     * declare the media type [IANA.MediaTypes] of this complete JWS.  This
     * is intended for use by the application when more than one kind of
     * object could be present in an application data structure that can
     * contain a JWS
     * @return StringOrURI
     */
    public function getType();

    /**
     * @param string $name
     * @return JOSEHeaderParam
     */
    public function getHeaderByName($name);

}