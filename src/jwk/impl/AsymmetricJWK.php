<?php namespace jwk\impl;
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
use jwk\exceptions\InvalidJWKVisibilityException;
use jwk\IAsymmetricJWK;
use jwk\JSONWebKeyVisibility;
use jwk\PublicJSONWebKeyParameters;
use security\exceptions\X509CertMismatchException;
use security\PrivateKey;
use security\PublicKey;
use security\x509\X509Certificate;
use security\x509\X509CertificateFactory;
use utils\json_types\JsonArray;
use utils\json_types\StringOrURI;
/**
 * Class AsymmetricJWK
 * @package jwk\impl
 */
abstract class AsymmetricJWK
    extends JWK
    implements IAsymmetricJWK
{

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
     * @var X509Certificate[]
     */
    protected $x509_certificates_chain = [];

    /**
     * @param array $headers
     * @throws X509CertMismatchException
     */
    protected function __construct(array $headers = array())
    {
        parent::__construct($headers);

        if(count($headers) === 0 ) return;

        // certificates
        if(in_array(PublicJSONWebKeyParameters::X_509CertificateChain, $headers) && is_array($headers[PublicJSONWebKeyParameters::X_509CertificateChain])){

            // json array
            foreach($headers[PublicJSONWebKeyParameters::X_509CertificateChain] as $x509_pem){
                $this->x509_certificates_chain[] =  X509CertificateFactory::buildFromPEM($x509_pem);
            }

            if($this->checkX509CertMismatch()){
                throw new X509CertMismatchException;
            }

            $this->set[PublicJSONWebKeyParameters::X_509CertificateChain] = new JsonArray($headers[PublicJSONWebKeyParameters::X_509CertificateChain]);
        }

        if(in_array(PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint, $headers)){
            $this->set[PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint] = new StringOrURI($headers[PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint]) ;
        }

        if(in_array(PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint, $headers)){
            $this->set[PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint] = new StringOrURI($headers[PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint]);
        }

        if(in_array(PublicJSONWebKeyParameters::X_509Url, $headers)){
            $this->set[PublicJSONWebKeyParameters::X_509Url] = new StringOrURI($headers[PublicJSONWebKeyParameters::X_509Url]);
        }
    }

       /**
     * @return int
     */
    public function getVisibility()
    {
        return $this->visibility;
    }

    /**
     * @param int $visibility
     * @return $this
     * @throws InvalidJWKVisibilityException
     */
    public function setVisibility($visibility)
    {
        if(!in_array($visibility, JSONWebKeyVisibility::$valid_values))
            throw new InvalidJWKVisibilityException;
        $this->visibility = $visibility;
        return $this;
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

    /**
     * @return null | X509Certificate
     */
    public function getX509LeafCertificate(){
        return count($this->x509_certificates_chain) > 0 ? $this->x509_certificates_chain[0] : null;
    }


    /**
     * @return X509Certificate[]
     */
    public function getCertificateChain()
    {
        return $this->x509_certificates_chain;
    }

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha1Thumbprint($fallback_on_x5c = false)
    {
        $res = is_null($this[PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint])? null : $this[PublicJSONWebKeyParameters::X_509CertificateSHA_1_Thumbprint]->getString();
        if(empty($res) && $fallback_on_x5c){
            $x509 = $this->getX509LeafCertificate();
            if(!is_null($x509)){
                return $x509->getSHA_1_Thumbprint();
            }
        }
        return $res;
    }

    /**
     * @param bool $fallback_on_x5c
     * @return string
     */
    public function getX509CertificateSha256Thumbprint($fallback_on_x5c = false)
    {
        $res = is_null($this[PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint])? null : $this[PublicJSONWebKeyParameters::X_509CertificateSHA_256_Thumbprint]->getString();
        if(empty($res) && $fallback_on_x5c){
            $x509 = $this->getX509LeafCertificate();
            if(!is_null($x509)){
                return $x509->getSHA_256_Thumbprint();
            }
        }
        return $res;
    }

    /**
     * @return string
     */
    public function getX509Url()
    {
        return is_null($this[PublicJSONWebKeyParameters::X_509Url])? null : $this[PublicJSONWebKeyParameters::X_509Url]->getString();
    }

    /**
     * @return bool
     */
    protected function checkX509CertMismatch(){
        $x509 = $this->getX509LeafCertificate();
        return !is_null($x509) && $x509->getPublicKey() !== $this->public_key->getStrippedEncoded();
    }

    /**
     * @param array $x5c
     * @return $this
     * @throws X509CertMismatchException
     */
    public function setX509CertificateChain(array $x5c){
        // json array
        foreach($x5c as $x509_pem){
            array_push($this->x509_certificates_chain, X509CertificateFactory::buildFromPEM($x509_pem));
        }

        if($this->checkX509CertMismatch()){
            throw new X509CertMismatchException;
        }

        $this->set[PublicJSONWebKeyParameters::X_509CertificateChain] = new JsonArray($x5c);

        return $this;
    }
}