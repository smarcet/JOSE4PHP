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

namespace jwt\impl;

use jwt\IJOSEHeader;
use jwt\JOSEHeaderParam;
use jwt\RegisteredJOSEHeaderNames;
use utils\JsonObject;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;

/**
 * Class JOSEHeader
 * @package jwt\impl
 */
class JOSEHeader
    extends JsonObject
    implements IJOSEHeader {

    /**
     * @param StringOrURI $alg
     * @param StringOrURI $type
     * @param StringOrURI $cty
     * @param JsonValue   $kid
     */
    public function __construct(StringOrURI $alg, StringOrURI $type, StringOrURI $cty = null, JsonValue  $kid = null){

        $this->set[RegisteredJOSEHeaderNames::Algorithm]   = $alg;
        $this->set[RegisteredJOSEHeaderNames::Type]        = $type;
        $this->set[RegisteredJOSEHeaderNames::ContentType] = $cty;
        $this->set[RegisteredJOSEHeaderNames::KeyID]       = $kid;
    }

    /**
     * @return StringOrURI
     */
    public function getAlgorithm()
    {
        return $this[RegisteredJOSEHeaderNames::Algorithm];
    }

    /**
     * @return JsonValue
     */
    public function getKeyID()
    {
        return $this[RegisteredJOSEHeaderNames::KeyID];
    }

    /**
     * @return StringOrURI
     */
    public function getContentType()
    {
        return $this[RegisteredJOSEHeaderNames::ContentType];
    }

    /**
     * @return StringOrURI
     */
    public function getType()
    {
        return $this[RegisteredJOSEHeaderNames::Type];
    }

    /**
     * @param JOSEHeaderParam $header_param
     * @return void
     */
    public function addHeader(JOSEHeaderParam $header_param)
    {

    }
}