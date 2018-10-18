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
use utils\json_types\JsonValue;
/**
 * Class JWTClaim
 * @package jwt
 *
 * A piece of information asserted about a subject.  A claim is
 * represented as a name/value pair consisting of a Claim Name and a
 * Claim Value.
 */
class JWTClaim {

    /**
     * @var string
     * The name portion of a claim representation. A Claim Name is
     * always a string.
     */
    private $name;

    /**
     * @var JsonValue
     * The value portion of a claim representation. A Claim Value can be
     * any JSON value.
     */
    private $value;

    /**
     * @param string $name
     * @param JsonValue $value
     */
    public function __construct($name , $value){
        $this->name  = $name;
        $this->value = $value;
    }


    /**
     * @return string
     */
    public function getName(){
        return $this->name;
    }

    /**
     * @return JsonValue
     */
    public function getValue(){
        return $this->value;
    }

    /**
     * @return array|bool|int|string|\utils\json_types\IJsonObject
     */
    public function getRawValue(){
        return $this->getValue()->getValue();
    }

}