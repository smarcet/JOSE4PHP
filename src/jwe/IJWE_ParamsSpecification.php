<?php namespace jwe;
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
use jwk\IJWK;
use jws\IJWSPayloadSpec;
use utils\json_types\JsonValue;
use utils\json_types\StringOrURI;
/**
 * Interface IJWE_ParamsSpecification
 * @package jwe
 */
interface IJWE_ParamsSpecification extends IJWE_Specification {

    /**
     * @return IJWK
     */
    public function getRecipientKey();

    /**
     * @return StringOrURI
     */
    public function getAlg();

    /**
     * @return StringOrURI
     */
    public function getEnc();


    /**
     * @return JsonValue
     */
    public function getZip();

    /**
     * @return IJWSPayloadSpec
     */
    public function getPayload();

}