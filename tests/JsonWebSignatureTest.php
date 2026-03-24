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
use jwa\JSONWebSignatureAndEncryptionAlgorithms;

use jwt\RegisteredJWTClaimNames;
use jwt\RegisteredJOSEHeaderNames;
use jwt\utils\JWTClaimSetFactory;

use jwk\impl\RSAJWKPEMPrivateKeySpecification;
use jwk\impl\OctetSequenceJWKSpecification;
use jwk\impl\RSAJWKParamsPublicKeySpecification;
use jwk\RSAKeysParameters;
use jwk\JSONWebKeyParameters;
use jwk\impl\OctetSequenceJWKFactory;
use jwk\impl\RSAJWKFactory;

use jws\impl\specs\JWS_ParamsSpecification;
use jws\impl\specs\JWS_CompactFormatSpecification;
use jws\JWSFactory;

use jwk\impl\RSAJWKPEMPublicKeySpecification;

use utils\json_types\StringOrURI;
/**
 * Class JsonWebSignatureTest
 */
final class JsonWebSignatureTest extends \PHPUnit\Framework\TestCase {

    /**
     * @throws \jwk\exceptions\InvalidJWKAlgorithm
     * @throws \jwk\exceptions\InvalidJWKType
     */
    public function testSignAndVerificationToken()
    {

        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                OctetSequenceJWKSpecification::GenerateSecret,
                JSONWebSignatureAndEncryptionAlgorithms::HS512
            )
        );

        $key->setId('sym_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::HS512);

        $jws = JWSFactory::build
        (
            new JWS_ParamsSpecification
            (
                $key,
                $alg,
                $claim_set
            )
        );

        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build( new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $res = $jws_1->setKey($key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    /**
     * @throws \jwk\exceptions\InvalidJWKAlgorithm
     * @throws \jwk\exceptions\InvalidJWKType
     */
    public function testSignAndVerificationTokenRSA(){

        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        )
        ;
        //load server private key.
        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::PS512
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS512);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key,$alg, $claim_set) );
        // and sign with server private key
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        // then on client side, load the JWS from compact format
        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        // get the server public key from jose header ..

        $public_key =  $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);

        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        // and re built it from params
        $public_key = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification($public_key[RSAKeysParameters::Modulus],
                                                                                  $public_key[RSAKeysParameters::Exponent],
                                                                                  $public_key[JSONWebKeyParameters::Algorithm],
                                                                                  $public_key[JSONWebKeyParameters::PublicKeyUse]));

        //set the server public key and then proceed to verify signature

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);
    }


    /**
     * @throws \jwk\exceptions\InvalidJWKAlgorithm
     * @throws \jwk\exceptions\InvalidJWKType
     */
    public function testSignAndVerificationTokenRSAUnicode()
    {

        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'セバスチャン',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );
        //load server private key.
        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::PS512
            )
        );

        $key->setId('server_key');
        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS512);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key,$alg, $claim_set) );
        // and sign with server private key
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        // then on client side, load the JWS from compact format
        $jws_1 = JWSFactory::build
        (
            new JWS_CompactFormatSpecification
            (
                $compact_serialization
            )
        );

        $this->assertTrue(!is_null($jws_1));

        // get the server public key from jose header ..

        $public_key =  $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);

        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        // and re built it from params
        $public_key = RSAJWKFactory::build
        (
            new RSAJWKParamsPublicKeySpecification
            (
                $public_key[RSAKeysParameters::Modulus],
                $public_key[RSAKeysParameters::Exponent],
                $public_key[JSONWebKeyParameters::Algorithm],
                $public_key[JSONWebKeyParameters::PublicKeyUse]
            )
        );

        //set the server public key and then proceed to verify signature

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);

        $this->assertTrue($jws_1->getClaimSet()->getIssuer()->getString() === 'セバスチャン');
    }

    /**
     * @throws \jwk\exceptions\InvalidJWKAlgorithm
     * @throws \jwk\exceptions\InvalidJWKType
     * @throws \jws\exceptions\JWSInvalidJWKException
     * @throws \jws\exceptions\JWSInvalidPayloadException
     * @throws \jws\exceptions\JWSNotSupportedAlgorithm
     */
    public function testSignAndVerificationRS256WithPass(){

        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'セバスチャン',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        //load server private key rs256 with password
        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_with_pass_rs256,
               "1qaz2wsx",
                JSONWebSignatureAndEncryptionAlgorithms::RS256
            )
        );

        $key->setId('server_key');
        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS256);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key,$alg, $claim_set) );
        // and sign with server private key
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        // then on client side, load the JWS from compact format
        $jws_1 = JWSFactory::build
        (
            new JWS_CompactFormatSpecification
            (
                $compact_serialization
            )
        );

        $this->assertTrue(!is_null($jws_1));

        // get the server public key from jose header ..

        $public_key =  $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);

        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        // and re built it from params
        $public_key = RSAJWKFactory::build
        (
            new RSAJWKParamsPublicKeySpecification
            (
                $public_key[RSAKeysParameters::Modulus],
                $public_key[RSAKeysParameters::Exponent],
                $public_key[JSONWebKeyParameters::Algorithm],
                $public_key[JSONWebKeyParameters::PublicKeyUse]
            )
        );

        //set the server public key and then proceed to verify signature

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);

        $this->assertTrue($jws_1->getClaimSet()->getIssuer()->getString() === 'セバスチャン');
    }

    public function testSignAndVerificationHS256()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                OctetSequenceJWKSpecification::GenerateSecret,
                JSONWebSignatureAndEncryptionAlgorithms::HS256
            )
        );

        $key->setId('sym_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::HS256);

        $jws = JWSFactory::build
        (
            new JWS_ParamsSpecification
            (
                $key,
                $alg,
                $claim_set
            )
        );

        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build( new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $res = $jws_1->setKey($key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testSignAndVerificationHS384()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                OctetSequenceJWKSpecification::GenerateSecret,
                JSONWebSignatureAndEncryptionAlgorithms::HS384
            )
        );

        $key->setId('sym_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::HS384);

        $jws = JWSFactory::build
        (
            new JWS_ParamsSpecification
            (
                $key,
                $alg,
                $claim_set
            )
        );

        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build( new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $res = $jws_1->setKey($key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testSignAndVerificationRS384()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key, $alg, $claim_set) );
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $public_key = $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);
        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        $public_key = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification($public_key[RSAKeysParameters::Modulus],
                                                                                  $public_key[RSAKeysParameters::Exponent],
                                                                                  $public_key[JSONWebKeyParameters::Algorithm],
                                                                                  $public_key[JSONWebKeyParameters::PublicKeyUse]));

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testSignAndVerificationRS512()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS512
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS512);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key, $alg, $claim_set) );
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $public_key = $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);
        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        $public_key = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification($public_key[RSAKeysParameters::Modulus],
                                                                                  $public_key[RSAKeysParameters::Exponent],
                                                                                  $public_key[JSONWebKeyParameters::Algorithm],
                                                                                  $public_key[JSONWebKeyParameters::PublicKeyUse]));

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testSignAndVerificationPS256()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::PS256
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS256);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key, $alg, $claim_set) );
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $public_key = $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);
        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        $public_key = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification($public_key[RSAKeysParameters::Modulus],
                                                                                  $public_key[RSAKeysParameters::Exponent],
                                                                                  $public_key[JSONWebKeyParameters::Algorithm],
                                                                                  $public_key[JSONWebKeyParameters::PublicKeyUse]));

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testSignAndVerificationPS384()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
                'groups'                                => array('admin', 'sudo', 'devs')
            )
        );

        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::PS384
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS384);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key, $alg, $claim_set) );
        $compact_serialization = $jws->toCompactSerialization();

        $this->assertTrue(!is_null($jws));
        $this->assertTrue(!empty($compact_serialization));

        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $this->assertTrue(!is_null($jws_1));

        $public_key = $jws_1->getJOSEHeader()->getHeaderByName(RegisteredJOSEHeaderNames::JSONWebKey);
        $this->assertTrue(!is_null($public_key));

        $public_key = $public_key->getRawValue();
        $public_key = RSAJWKFactory::build(new RSAJWKParamsPublicKeySpecification($public_key[RSAKeysParameters::Modulus],
                                                                                  $public_key[RSAKeysParameters::Exponent],
                                                                                  $public_key[JSONWebKeyParameters::Algorithm],
                                                                                  $public_key[JSONWebKeyParameters::PublicKeyUse]));

        $res = $jws_1->setKey($public_key)->verify($alg->getString());

        $this->assertTrue($res);
    }

    public function testVerifyWithWrongKeyFails()
    {
        $claim_set = JWTClaimSetFactory::build
        (
            array
            (
                RegisteredJWTClaimNames::Issuer         => 'joe',
                RegisteredJWTClaimNames::ExpirationTime => 1300819380,
                "http://example.com/is_root"            => true,
            )
        );

        // Sign with key1
        $key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::PS512
            )
        );

        $key->setId('server_key');

        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::PS512);
        $jws = JWSFactory::build( new JWS_ParamsSpecification($key, $alg, $claim_set) );
        $compact_serialization = $jws->toCompactSerialization();

        // Parse and try to verify with key2's public key (wrong key)
        $jws_1 = JWSFactory::build(new JWS_CompactFormatSpecification($compact_serialization));

        $wrong_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::PS512
            )
        );

        // Use same kid to bypass kid-mismatch guard
        $wrong_key->setId('server_key');

        $res = $jws_1->setKey($wrong_key)->verify($alg->getString());

        $this->assertFalse($res);
    }
}