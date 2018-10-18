<?php namespace jwa\cryptographic_algorithms\key_management\modes;
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
 * Interface KeyAgreementWithKeyWrapping
 * @package jwa\cryptographic_algorithms\key_management\modes
 * @marker_interface
 *
 * A Key Management Mode in which a key agreement algorithm is used
 * to agree upon a symmetric key used to encrypt the CEK value to the
 * intended recipient using a symmetric key wrapping algorithm.
 */
interface KeyAgreementWithKeyWrapping {

}