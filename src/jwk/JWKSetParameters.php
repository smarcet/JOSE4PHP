<?php namespace jwk;
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
 * Class JWKSetParameters
 * @package jwk
 */
abstract class JWKSetParameters {

    /**
     *
     * The value of the "keys" parameter is an array of JWK values.  By
     * default, the order of the JWK values within the array does not imply
     * an order of preference among them, although applications of JWK Sets
     * can choose to assign a meaning to the order for their purposes, if
     * desired.
     */
    const Keys = 'keys';
}