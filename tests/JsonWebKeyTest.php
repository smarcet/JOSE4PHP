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
}