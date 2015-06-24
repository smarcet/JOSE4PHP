<?php
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

namespace jwk\impl;

use jwk\exceptions\InvalidJWKAlgorithm;
use jwk\exceptions\InvalidJWKType;
use jwk\exceptions\InvalidJWKUseException;
use jwk\IAsymetricJWK;
use security\PrivateKey;
use security\PublicKey;


/**
 * Class AsymetricJWK
 * @package jwk\impl
 */
abstract class AsymetricJWK
    extends JWK
    implements IAsymetricJWK {

    /**
     * @var int
     */
    protected $visibility;

    /**
     * @var PrivateKey
     */
    protected $private_key;

    /**
     * @var PublicKey
     */
    protected $public_key;

    /**
     * @param array $headers
     * @throws InvalidJWKAlgorithm
     * @throws InvalidJWKType
     * @throws InvalidJWKUseException
     */
    protected function __construct(array $headers = array()){
        parent::__construct($headers);
        if(count($headers) === 0 ) return;
    }

    /**
     * @return string[]
     */
    public function getCertificateChain()
    {
        // TODO: Implement getCertificateChain() method.
    }

    /**
     * @return string
     */
    public function getLeafCertificate()
    {
        // TODO: Implement getLeafCertificate() method.
    }

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha1Thumbprint($fallback_on_x5c = false)
    {
        // TODO: Implement getX509CertificateSha1Thumbprint() method.
    }

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha256Thumbprint($fallback_on_x5c = false)
    {
        // TODO: Implement getX509CertificateSha256Thumbprint() method.
    }

    /**
     * @return string
     */
    public function getX509Url()
    {
        // TODO: Implement getX509Url() method.
    }

    /**
     * @return int
     */
    public function getVisibility(){
        return $this->visibility;
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey()
    {
        return  $this->private_key;
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey()
    {
        return  $this->public_key;
    }
}