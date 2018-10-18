<?php namespace utils;
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
 * Class Base64UrlRepresentation
 * @package utils
 */
final class Base64UrlRepresentation implements IObjectRepresentation{

    const Padding = 4;
    /**
     * @param mixed $input
     * @return mixed
     */
    public function encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * @param mixed $input
     * @return mixed
     */
    public function decode($input)
    {
        $remainder = strlen($input) % self::Padding;
        if ($remainder) {
            $padlen = self::Padding - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}