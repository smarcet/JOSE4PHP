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
use jwt\utils\JWTClaimSetFactory;
use jwt\RegisteredJWTClaimNames;
use jwk\impl\RSAJWKPEMPrivateKeySpecification;
use jwk\impl\RSAJWKFactory;
use jws\payloads\JWSPayloadFactory;
use jwe\impl\JWEFactory;
use jwa\JSONWebSignatureAndEncryptionAlgorithms;
use jwk\JSONWebKeyPublicKeyUseValues;
use utils\json_types\StringOrURI;
use jwk\impl\RSAJWKPEMPublicKeySpecification;

class JsonWebEncryptionTest extends PHPUnit_Framework_TestCase {


    public function testCreate(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        $key  = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));


        $key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build($key, $alg, JWSPayloadFactory::build($claim_set));

        $payload = $jws->serialize();

        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build($recipient_key, $alg, $enc, JWSPayloadFactory::build($payload));
        $res     =  $jwe->serialize();

        $this->assertTrue(!empty($res));
    }
}