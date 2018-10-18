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
use jwe\exceptions\JWEInvalidCompactFormatException;
use jwt\IBasicJWT;
use jwt\utils\JWTRawSerializer;
use jwt\utils\JOSEHeaderSerializer;
/**
 * Class JWESerializer
 * @package jwe\impl
 * @access internal
 */
final class JWESerializer
{

    /**
     * @param IJWESnapshot $jwe_snapshot
     * @return string
     */
    static public function serialize(IJWESnapshot $jwe_snapshot)
    {

        list($header, $enc_cek, $iv, $cipher_text, $tag) = $jwe_snapshot->take();

        $header      = JWEJOSEHeaderSerializer::serialize($header);
        $enc_cek     = JWTRawSerializer::serialize($enc_cek);
        $iv          = JWTRawSerializer::serialize($iv);
        $cipher_text = JWTRawSerializer::serialize($cipher_text);
        $tag         = JWTRawSerializer::serialize($tag);

        return sprintf('%s.%s.%s.%s.%s', $header, $enc_cek, $iv, $cipher_text, $tag);
    }

    /**
     * @param $input
     * @return array
     * @throws JWEInvalidCompactFormatException
     */
    static public function deserialize($input){
        $parts = explode(IBasicJWT::SegmentSeparator, $input);
        if (count($parts) !== 5) throw new JWEInvalidCompactFormatException;

        $header = JWEJOSEHeaderSerializer::deserialize($parts[0]);
        $enc_cek = JWTRawSerializer::deserialize($parts[1]);
        $iv = JWTRawSerializer::deserialize($parts[2]);
        $cipher_text = JWTRawSerializer::deserialize($parts[3]);
        $tag = JWTRawSerializer::deserialize($parts[4]);

        return array($header, $enc_cek, $iv, $cipher_text, $tag);
    }

}