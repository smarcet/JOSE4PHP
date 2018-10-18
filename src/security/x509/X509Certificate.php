<?php namespace security\x509;
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
 * Interface X509Certificate
 * @package security\x509
 */
interface X509Certificate {

    /**
     * @return string
     */
    public function getPEM();

    /**
     * @return string
     */
    public function getSHA_1_Thumbprint();

    /**
     * @return string
     */
    public function getSHA_256_Thumbprint();

    /**
     * @return string
     */
    public function getPublicKey();

    /**
     * @return array
     */
    public function getInfo();
}