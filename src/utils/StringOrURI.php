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

namespace utils;

/**
 * Class StringOrURI
 * @package utils
 * A JSON string value, with the additional requirement that while
 * arbitrary string values MAY be used, any value containing a ":"
 * character MUST be a URI [RFC3986].  StringOrURI values are
 * compared as case-sensitive strings with no transformations or
 * canonicalizations applied.
 */
class StringOrURI extends JsonValue {

    public function getString(){
        return $this->value;
    }

    /**
     * @return string
     */
    public function getUri(){
        return '';
    }

    /**
     * @return bool
     */
    public function isString(){
        return true;
    }

    /**
     * @return bool
     */
    public function isUri(){
        return false;
    }
}