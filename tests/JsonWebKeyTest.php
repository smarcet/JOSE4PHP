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
use security\rsa\RSAFacade;
use jwk\impl\RSAJWKSpecification;
use security\rsa\RSAPublicKey;
use \jwk\impl\RSAJWKPEMPrivateKeySpecification;
use \jwk\impl\JWKSet;
use jwk\impl\RSAJWKParamsPublicKeySpecification;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use security\x509\X509CertificateFactory;
use utils\json_types\Base64urlUInt;
/**
 * Class JsonWebKeyTest
 */
final class JsonWebKeyTest extends PHPUnit_Framework_TestCase {

    public function testCreate(){
        $jwk = RSAJWKFactory::build(new RSAJWKSpecification(JSONWebSignatureAndEncryptionAlgorithms::RS512));
        $this->assertTrue(!is_null($jwk));
    }

    public function testRSAFacade(){

        $keys = RSAFacade::getInstance()->buildKeyPair(2048);

        $this->assertTrue(!is_null($keys));
    }

    public function testCreateFromParams(){

        $jwk = RSAJWKFactory::build(
            new RSAJWKParamsPublicKeySpecification
            (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                'AQAB'
            )
        );
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

    public function testLoadFromJsonJWKSet(){

        $json_jwk_set = <<<JWK_SET
        {
 "keys":[
  {
   "kty":"RSA",
   "n":"w9x1sXTkzuxJRHfLYdCv1DN2SsD90ufkSt_HOSjM7PSFsh-yGrqP85Hia2y_2bogz03L4GUrrGBXk8OlKxEK_U1QxhhRYyFKuyo2Y6jx2t8RXCE1duskyRikcEFMQtfacZiNeLlr_0SqlxQJBNgBi_e3g3UIFzyEXpRQS7X0AJ6xuRLT7-Nl1BT3QSB-cBsENgHb10zQNaOG3VnyNehrtofHzPyF4PO4q1dVK7qaqyjp50sX7ya7TXqG3e0dNV-vyIN5AVG-UKOGiON8XB9UQj0x4zWiIa7PYG298m6Jx_26ZLNU0RyF3kXbUzwDBdpOyhXjoyOwQ1V42BxDyqhaow",
   "e":"AQAB",
   "kid":"PHPOP-00S",
   "use":"sig"
  },
    {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "use":"enc",
          "kid":"2011-04-29"},

         {"kty":"RSA",
      "use":"sig",
      "kid":"1b94c",
      "use":"enc",
      "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
      "e":"AQAB",
      "x5c":
       [
            "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
       ]
     }
 ]
}
JWK_SET;

        $jwk_set = JWKSet::fromJson($json_jwk_set);

        $this->assertTrue(!is_null($jwk_set));
        $count = count($jwk_set->getKeys());
        $this->assertTrue( $count === 3);

        $jwk = $jwk_set->getKeyById("2011-04-29");

        $this->assertTrue(!is_null($jwk));


    }
}