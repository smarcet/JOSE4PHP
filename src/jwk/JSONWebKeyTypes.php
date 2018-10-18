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
 * Class JSONWebKeyTypes
 * @package jwk
 *
 * https://tools.ietf.org/html/rfc7518#section-6.1
 *
 * +-------------+--------------------------------+--------------------+
 * | "kty" Param | Key Type                       | Implementation     |
 * | Value       |                                | Requirements       |
 * +-------------+--------------------------------+--------------------+
 * | EC          | Elliptic Curve [DSS]           | Recommended+       |
 * | RSA         | RSA [RFC3447]                  | Required           |
 * | oct         | Octet sequence (used to        | Required           |
 * |             | represent symmetric keys)      |                    |
 * +-------------+--------------------------------+--------------------+
 *
 */
abstract class JSONWebKeyTypes {

    const  EllipticCurve = 'EC';

    const  RSA = 'RSA';

    const  OctetSequence = 'OCT';


    public static $valid_keys_set = [
        self::OctetSequence,
        self::RSA,
        self::EllipticCurve
    ];

    public static $supported_keys = [
        self::RSA,
    ];

}