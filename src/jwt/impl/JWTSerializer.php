<?php namespace jwt\impl;
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
use jwt\exceptions\InvalidJWTException;
use jwt\IBasicJWT;
use jwt\utils\JOSEHeaderSerializer;
use jwt\utils\JWTClaimSetSerializer;
use jwt\utils\JWTRawSerializer;
/**
 * Class JWTSerializer
 * @package jwt\impl
 * @access internal
 */
final class JWTSerializer {

    /**
     * @param IJWTSnapshot $jwt_snapshot
     * @return string
     */
    static public function serialize(IJWTSnapshot $jwt_snapshot){
        list($header, $payload, $signature) = $jwt_snapshot->take();

        $e_header    = JOSEHeaderSerializer::serialize($header);
        $e_payload   = ($header->getType()->getString() === 'JWT') ?  JWTClaimSetSerializer::serialize($payload) : JWTRawSerializer::serialize($payload);
        $e_signature = JWTRawSerializer::serialize($signature);

        return sprintf('%s.%s.%s', $e_header, $e_payload, $e_signature);
    }

    /**
     * @param string $input
     * @return array
     * @throws InvalidJWTException
     */
    static public function deserialize($input){

        $e_parts = explode(IBasicJWT::SegmentSeparator, $input);

        if(count($e_parts) < 2)
            throw new InvalidJWTException(sprintf('%s has only 2 or less encoded parts!'));
        $e_header    = $e_parts[0];
        $e_payload   = $e_parts[1];
        $e_signature = count($e_parts)>2 ? $e_parts[2] : '';
        $header    = JOSEHeaderSerializer::deserialize($e_header);
        $payload   = ($header->getType()->getString() === 'JWT') ? JWTClaimSetSerializer::deserialize($e_payload) : JWTRawSerializer::deserialize($e_payload);
        $signature = !empty($e_signature) ? JWTRawSerializer::deserialize($e_signature): '';
        return array($header, $payload, $signature);
    }
}