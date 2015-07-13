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

namespace jwk;

use jwk\exceptions\InvalidJWKVisibilityException;
use security\exceptions\X509CertMismatchException;
use security\PrivateKey;
use security\PublicKey;
use security\KeyPair;
use security\x509\X509Certificate;

/**
 * Interface IAsymmetricJWK
 * @package jwk
 */
interface IAsymmetricJWK extends IJWK {

    /**
     * @return PrivateKey
     */
    public function getPrivateKey();

    /**
     * @return PublicKey
     */
    public function getPublicKey();

    /**
     * @return X509Certificate[]
     */
    public function getCertificateChain();

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha1Thumbprint($fallback_on_x5c = false);

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha256Thumbprint($fallback_on_x5c = false);

    /**
     * @return string
     */
    public function getX509Url();

    /**
     * @return int
     */
    public function getVisibility();

    /**
     * @return null | X509Certificate
     */
    public function getX509LeafCertificate();

    /**
     * @param int $visibility
     * @return $this
     * @throws InvalidJWKVisibilityException
     */
    public function setVisibility($visibility);

    /**
     * @param array $x5c
     * @return $this
     * @throws X509CertMismatchException
     */
    public function setX509CertificateChain(array $x5c);

    // factory methods

    /**
     * @param KeyPair $keys
     * @return IAsymmetricJWK
     */
    static public function fromKeys(KeyPair $keys);

    /**
     * @param PublicKey $public_key
     * @return IAsymmetricJWK
     */
    static public function fromPublicKey(PublicKey $public_key);

    /**
     * @param PrivateKey $private_key
     * @return IAsymmetricJWK
     */
    static public function fromPrivateKey(PrivateKey $private_key);

}