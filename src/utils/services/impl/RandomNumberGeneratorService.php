<?php namespace utils\services\impl;
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
use utils\ByteUtil;
use utils\services\IService;
/**
 * Class RandomNumberGeneratorService
 * @package utils\services\impl
 */
final class RandomNumberGeneratorService implements IService {

    /**
     * @throws \RuntimeException
     * @return mixed
     */
    public function invoke()
    {
        if(func_num_args() <= 0) throw new \RuntimeException('you must pass len as arg!');
        $byte_len = func_get_arg(0);
        return ByteUtil::randomBytes($byte_len);
    }
}