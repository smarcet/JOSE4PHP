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
use utils\exceptions\JsonParseException;
use utils\json_types\IJsonObject;
use utils\json_types\JsonValue;

/**
 * Class JsonObject
 * @package utils
 */
class JsonObject implements \ArrayAccess, IJsonObject {

    /**
     * @var array
     */
    protected $set = array();


    public function offsetSet($offset, $value)
    {
        throw new \LogicException;
    }

    public function offsetGet($offset)
    {
        return isset($this->set[$offset]) ? $this->set[$offset] : null;
    }

    public function offsetExists($offset)
    {
        return array_key_exists($offset, $this->set);
    }

    public function offsetUnset($offset)
    {
        throw new \LogicException;
    }


    /**
     * @return string
     * @throws exceptions\JsonParseException
     */
    public function toJson()
    {
        $input = $this->toArray();
        $json  = json_encode($input);
        $json  = str_replace('\/','/', $json);

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            self::handleJsonError($errno);
        } elseif ($json === 'null' ) {
            throw new JsonParseException('Null resul with non-null input');
        }
        return $json;
    }


    /**
     * @param int $errno
     * @throws exceptions\JsonParseException
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH     => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX    => 'Syntax error, malformed JSON'
        );
        throw new JsonParseException(
            isset($messages[$errno])
                ? $messages[$errno]
                : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * @return array
     */
    public function toArray()
    {
       $res = array();
       foreach($this->set as $k => $jv){
           if($jv instanceof JsonValue){
               $res[$k] = $jv->getValue();
           }
       }
       return $res;
    }
}