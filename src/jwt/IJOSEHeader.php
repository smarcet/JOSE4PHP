<?php namespace jwt;
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
 * Interface IJOSEHeader
 * @package jwt
 *
 * For a JWT object, the members of the JSON object represented by the
 * JOSE Header describe the cryptographic operations applied to the JWT
 * and optionally, additional properties of the JWT.  Depending upon
 * whether the JWT is a JWS or JWE, the corresponding rules for the JOSE
 * Header values apply.
 * This specification further specifies the use of the following Header
 * Parameters in both the cases where the JWT is a JWS and where it is a
 * JWE.
 */
interface IJOSEHeader extends IReadOnlyJOSEHeader {


    /**
     * @param JOSEHeaderParam $header_param
     * @return void
     */
    public function addHeader(JOSEHeaderParam $header_param);

}