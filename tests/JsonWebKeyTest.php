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

use jwk\impl\RSAJWKFactory;
use jwk\impl\RSAJWKKeyLengthSpecification;
use security\rsa\RSAFacade;
use jwk\impl\RSAJWKSpecification;
use security\rsa\RSAPublicKey;
use \jwk\impl\RSAJWKPEMPrivateKeySpecification;
use \jwk\impl\JWKSet;
use jwk\impl\RSAJWKParamsPublicKeySpecification;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use security\x509\X509CertificateFactory;
use security\x509\X509Certificate;

/**
 * Class JsonWebKeyTest
 */
class JsonWebKeyTest extends PHPUnit_Framework_TestCase {

    public function testCreate(){
        $jwk = RSAJWKFactory::build(new RSAJWKSpecification(JSONWebSignatureAndEncryptionAlgorithms::RS512));
        $this->assertTrue(!is_null($jwk));
    }

    public function testRSAFacade(){

        $keys = RSAFacade::getInstance()->buildKeyPair(2048);

        $this->assertTrue(!is_null($keys));
    }

    public function testCreateFromParams(){

        $jwk = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 'AQAB'));
        $jwk->setId('2011-04-29');

        $this->assertTrue(!is_null($jwk));

        $public_key = $jwk->getPublicKey();

        $this->assertTrue($public_key instanceof RSAPublicKey);

    }

    public function testCreateFromPrivateKey(){

        $jwk = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));

        $this->assertTrue(!is_null($jwk));
    }

    public function testCreateKeySet(){

        $jwk  = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));
        $jwk2 = RSAJWKFactory::build(new RSAJWKSpecification);
        $jwk->setId('k1');
        $jwk2->setId('k2');
        $set = new JWKSet(array($jwk, $jwk2 ));
        $res = $set->toJson();

        $this->assertTrue(!is_null($set));
        $this->assertTrue(!empty($res));
    }

    /**
     * @expectedException jwk\exceptions\InvalidJWKAlgorithm
     *
     */
    public function testInvalidRSAAlg(){
        RSAJWKFactory::build(new RSAJWKSpecification('test'));
    }


    public function testX509PEM(){

        $pem = <<<x509
MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB
gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD
VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1
wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg
NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV
QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w
YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH
YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66
s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6
SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn
fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq
PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk
aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA
QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL
+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1
zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL
2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo
4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq
gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==
x509;

        $x509 = X509CertificateFactory::buildFromPEM($pem);

        $should_fingerprint_sha1 = 'E2935E9C404BBF42692C876E816C5090EB1970AD';

        $this->assertTrue($x509->getSHA_1_Thumbprint() === $should_fingerprint_sha1);

        $should_fingerprint_sha256 = 'A499B6041A6407CCBBB42AAB58CD17DFB58E9904CEF33430F95A7156005BDB52';

        $this->assertTrue($x509->getSHA_256_Thumbprint() === $should_fingerprint_sha256);

        $public_key = $x509->getPublicKey();

        $this->assertTrue(!empty($public_key));
    }
}