<?php namespace jwe\impl;
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
use utils\services\Utils_Registry;
/**
 * Class IVFactory
 * @package jwe\impl
 */
final class IVFactory {

    /**
     * @param $size
     * @return string
     */
    static public function build($size){

        $generator = Utils_Registry::getInstance()->get(Utils_Registry::RandomNumberGeneratorService);
        return $generator->invoke($size / 8);
    }
}