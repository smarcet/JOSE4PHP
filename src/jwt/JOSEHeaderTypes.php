<?php namespace jwt;
/**
 * Copyright 2026 OpenStack Foundation
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
use utils\json_types\StringOrURI;
/**
 * Class JOSEHeaderTypes
 * @package jwt
 *
 * Values of the "typ" (type) Header Parameter (RFC 7515 §4.1.9, RFC 7519 §5.1).
 * "typ" is a media type: it is compared case-insensitively and the "application/"
 * prefix may be omitted. Explicitly typed JWTs (RFC 8725 §3.11) use a "+jwt" suffix.
 */
abstract class JOSEHeaderTypes {
    /**
     * Default type of a JWT (RFC 7519 §5.1)
     */
    const JWT = 'JWT';
    /**
     * Structured syntax suffix of explicitly typed JWTs, e.g. "at+jwt" (RFC 9068)
     */
    const JWTSuffix = '+jwt';
    /**
     * Media type prefix that may be omitted from "typ" (RFC 7515 §4.1.9)
     */
    const MediaTypePrefix = 'application/';

    /**
     * True when "typ" denotes a JWT claim set payload: absent ("typ" is OPTIONAL),
     * "JWT", or an explicitly typed JWT such as "at+jwt".
     * @param StringOrURI|null $typ
     * @return bool
     */
    public static function isJWT(?StringOrURI $typ): bool {
        if (is_null($typ)) return true;
        $value = strtolower((string)$typ->getString());
        if (str_starts_with($value, self::MediaTypePrefix))
            $value = substr($value, strlen(self::MediaTypePrefix));
        return $value === strtolower(self::JWT) || str_ends_with($value, self::JWTSuffix);
    }
}
