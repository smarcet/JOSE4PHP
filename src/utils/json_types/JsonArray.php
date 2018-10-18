<?php namespace utils\json_types;
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
 * Class JsonArray
 * @package utils\json_types
 */
class JsonArray extends JsonValue implements \ArrayAccess {

    public function __construct(array $values){
        parent::__construct($values);
    }

    public function offsetSet($offset, $value)
    {
        $this->value[$offset] = $value;
    }

    public function offsetGet($offset)
    {
        return isset($this->value[$offset]) ? $this->value[$offset] : null;
    }

    public function offsetExists($offset)
    {
        return array_key_exists($offset, $this->value);
    }

    public function offsetUnset($offset)
    {
        if ($this->offsetExists($offset))
            unset($this->value[$offset]);
    }

    public function append($value){
        array_push($this->value, $value);
    }

}