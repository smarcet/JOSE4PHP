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

namespace jwk\impl;


use jwk\exceptions\JWKInvalidIdentifierException;
use jwk\IJWK;
use jwk\IJWKSet;
use jwk\JWKSetParameters;
use utils\json_types\JsonArray;
use utils\JsonObject;

/**
 * Class JWKSet
 * @package jwk\impl
 */
final class JWKSet extends JsonObject implements IJWKSet {

    /**
     * @var JWK[]
     */
    private $keys   = array();

    private $keys_ids = array();

    /**
     * @param JWK[] $keys
     * @throws JWKInvalidIdentifierException
     */
    public function __construct(array $keys){

        $this->set[JWKSetParameters::Keys] = new JsonArray(array());

        foreach($keys as $k){
            $this->addKey($k);
        }
    }

    /**
     * @return IJWK[]
     */
    public function getKeys()
    {
        if(isset($this->set[JWKSetParameters::Keys]))
            return $this->set[JWKSetParameters::Keys]->getValue();
        return array();
    }

    /**
     * @param IJWK $key
     * @return void
     * @throws JWKInvalidIdentifierException
     */
    public function addKey(IJWK $key)
    {
        $id = $key->getId();
        if(empty($id))
            throw new JWKInvalidIdentifierException('key id is empty!');
        if(array_key_exists($id->getValue(), $this->keys_ids))
            throw new JWKInvalidIdentifierException(sprintf('id %s already exists!'), $key->getId()->getValue());

        if(!isset($this->set[JWKSetParameters::Keys]))
            $this->set[JWKSetParameters::Keys] = new JsonArray(array());

        $keys = $this->set[JWKSetParameters::Keys];
        $keys[] = $key;
        $this->set[JWKSetParameters::Keys] = $keys ;
        $this->keys_ids[$id->getValue()] = $id->getValue();
    }
}