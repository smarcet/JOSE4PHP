<?php namespace utils\factories;
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
use jwe\impl\JWEFactory;
use jwe\impl\specs\JWE_CompactFormatSpecification;
use jws\impl\specs\JWS_CompactFormatSpecification;
use jws\JWSFactory;
use jwt\IBasicJWT;
use jwk\exceptions\InvalidJWKType;
use jwt\impl\UnsecuredJWT;
use jwt\utils\JOSEHeaderSerializer;
use utils\exceptions\InvalidCompactSerializationException;
/**
 * Class BasicJWTFactory
 * @package utils\factories
 */
final class BasicJWTFactory
{
    /**
     * https://tools.ietf.org/html/rfc7516#section-9
     * @param string $compact_serialization
     * @return IBasicJWT
     * @throws InvalidJWKType
     * @throws InvalidCompactSerializationException
     */
    static public function build($compact_serialization)
    {
        $segments = explode(IBasicJWT::SegmentSeparator, $compact_serialization);
        // JWSs have three segments separated by two period ('.') characters.
        // JWEs have five segments separated by four period ('.') characters.
        switch(count($segments))
        {
            case 3:
                // JWS or unsecured one
                $header = JOSEHeaderSerializer::deserialize($segments[0]);
                if($header->getAlgorithm()->getString() === 'none' && empty($segments[2]))
                    return UnsecuredJWT::fromCompactSerialization($compact_serialization);
                return JWSFactory::build( new JWS_CompactFormatSpecification($compact_serialization) );
            break;
            case 5:
                // JWE
                return JWEFactory::build( new JWE_CompactFormatSpecification($compact_serialization) );
            break;
            default:
                throw new InvalidCompactSerializationException;
            break;
        }
        return null;
    }
}