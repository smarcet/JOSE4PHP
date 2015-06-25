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
use jws\JWSFactory;
use \jws\JWSupportedSigningAlgorithms;
use \jwk\impl\RSAJWKFactory;
use jwk\impl\OctetSequenceJWKFactory;
use jwt\utils\JWTClaimSetFactory;
use jwt\RegisteredJWTClaimNames;
use jws\impl\JWS;
use jwk\impl\RSAJWKPEMPrivateKeySpecification;
use jwk\impl\OctetSequenceJWKSpecification;
use jws\payloads\JWSPayloadFactory;
use utils\json_types\StringOrURI;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
/**
 * Class JsonWebSignatureTest
 */
final class JsonWebSignatureTest extends PHPUnit_Framework_TestCase {


    public function testSignAndVerificationToken(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        $key = OctetSequenceJWKFactory::build(new OctetSequenceJWKSpecification);
        $key->setId('sym_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::HS256);
        $jws = JWSFactory::build($key, $alg, JWSPayloadFactory::build($claim_set));

        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 =  JWS::fromCompactSerialization($compact_serialization);

        $this->assertTrue(!is_null($jws_1));

        $res = $jws_1->setKey($key)->verify($alg->getString());

        $this->assertTrue($res);
    }


    public function testSignAndVerificationTokenRSA(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        $key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));

        $key->setId('sym_key');
        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS512);
        $jws = JWSFactory::build($key,$alg, JWSPayloadFactory::build($claim_set));

        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 =  JWS::fromCompactSerialization($compact_serialization);

        $this->assertTrue(!is_null($jws_1));

        $res = $jws_1->setKey($key)->verify($alg->getString());

        $this->assertTrue($res);
    }
}