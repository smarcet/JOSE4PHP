<?php namespace jwt\impl;
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
class JOSEHeader extends JsonObject implements IJOSEHeader
{
    /**
     * @param StringOrURI $alg
     * @param StringOrURI|null $type
     * @param JsonValue|null $kid
     * @param StringOrURI|null $cty
     */
    public function __construct
    (
        StringOrURI $alg,
        StringOrURI $type = null,
        JsonValue   $kid  = null,
        StringOrURI $cty  = null
    )
    {

        $this->set[RegisteredJOSEHeaderNames::Algorithm]   = $alg;
        $this->set[RegisteredJOSEHeaderNames::Type]        = $type;
        $this->set[RegisteredJOSEHeaderNames::KeyID]       = $kid;
        $this->set[RegisteredJOSEHeaderNames::ContentType] = $cty;
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
        $this->set[$header_param->getName()] = $header_param->getValue();
    }

    /**
     * @param string $name
     * @return JOSEHeaderParam
     */
    public function getHeaderByName($name)
    {
        $value = $this[$name];
        if(is_null($value)) return null;
        return new JOSEHeaderParam($name, $value);
    }
}