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
use security\exceptions\InvalidX509CertificateException;
use phpseclib\File\X509;
/**
 * Class _X509Certificate
 * @package security\x509
 * @access private
 */
final class _X509Certificate implements X509Certificate {

    /**
     * @var array
     */
    private $info  = [];

    /**
     * @var X509|null
     */
    private $file = null;

    /**
     * @var null|string
     */
    private $original_pem = null;

    public function __construct($pem){

        $this->file = new X509();
        $this->info = $this->file->loadX509($pem);
        if($this->info === false) throw new InvalidX509CertificateException($pem);
        $this->original_pem = $pem;
    }

    /**
     * @return string
     */
    public function getPEM()
    {
       return $this->original_pem;
    }

    private function calculateThumbprint($alg){
        $pem = str_replace( array("\n","\r"), '', trim($this->original_pem));
        return strtoupper(hash($alg, base64_decode($pem)));
    }

    /**
     * @return string
     */
    public function getSHA_1_Thumbprint()
    {
        return $this->calculateThumbprint('sha1');
    }

    /**
     * @return string
     */
    public function getSHA_256_Thumbprint()
    {
        return $this->calculateThumbprint('sha256');
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        $pem = (string)$this->file->getPublicKey();
        $pem = preg_replace('/\-+BEGIN PUBLIC KEY\-+/','',$pem);
        $pem = preg_replace('/\-+END PUBLIC KEY\-+/','',$pem);
        $pem = str_replace( array("\n","\r","\t"), '', trim($pem));
        return $pem;
    }

    /**
     * @return array
     */
    public function getInfo()
    {
        return $this->info;
    }
}