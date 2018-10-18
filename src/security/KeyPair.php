<?php namespace security;
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
 * Class KeyPair
 * @package security
 */
final class KeyPair {

    /**
     * @var PrivateKey
     */
    private $private_key;
    /**
     * @var PublicKey
     */
    private $public_key;

    /**
     * @param PublicKey $public_key
     * @param PrivateKey $private_key
     */
    public function __construct(PublicKey $public_key, PrivateKey $private_key){

        $this->private_key = $private_key;
        $this->public_key  = $public_key;
    }

    /**
     * @return PublicKey
     */
    public function getPublic(){ return $this->public_key; }

    /**
     * @return PrivateKey
     */
    public function getPrivate(){ return $this->private_key; }

}