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

use jwt\utils\JWTClaimSetFactory;
use jwt\RegisteredJWTClaimNames;
use jwk\impl\RSAJWKPEMPrivateKeySpecification;
use jwk\impl\RSAJWKFactory;
use jwk\JSONWebKeyPublicKeyUseValues;
use jwk\impl\RSAJWKPEMPublicKeySpecification;

use jws\JWSFactory;
use jws\impl\specs\JWS_ParamsSpecification;
use jws\impl\specs\JWS_CompactFormatSpecification;

use jwe\impl\JWEFactory;
use jwe\impl\specs\JWE_CompactFormatSpecification;
use jwe\impl\specs\JWE_ParamsSpecification;
use jwe\compression_algorithms\CompressionAlgorithmsNames;

use utils\json_types\StringOrURI;
use utils\json_types\JsonValue;

use jwk\impl\OctetSequenceJWKSpecification;
use jwk\impl\OctetSequenceJWKFactory;
use jwe\exceptions\JWEInvalidCompactFormatException;
/**
 * Class JsonWebEncryptionTest
 */
final class JsonWebEncryptionTest extends \PHPUnit\Framework\TestCase
{

    public function testCreate()
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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        // and sign the jws with server private key
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));

        $payload = $jws->toCompactSerialization();

        //load client public key
        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);

        $jwe     = JWEFactory::build
        (
            new JWE_ParamsSpecification
            (
                $recipient_key,
                $alg,
                $enc,
                $payload
            )
        );

        // and finally encrypt it ...
        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));
    }

    public function testDecrypt()
    {
        // Round-trip test: sign a JWS, encrypt it as JWE, then decrypt and verify

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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt the JWS as a JWE using RSA1_5 + A256CBC-HS512
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Now decrypt the JWE
        $jwe_2 = JWEFactory::build
        (
            new JWE_CompactFormatSpecification
            (
                $jwe_compact_form
            )
        );

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        // Verify the inner JWS signature
        $jws_2 = JWSFactory::build(new JWS_CompactFormatSpecification($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );
        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testCreateDir()
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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        // and sign the jws with server private key
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));

        $payload = $jws->toCompactSerialization();

        //load shared key
        $shared_key =  OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                'this_is_a_secret_key_long_enough',
                JSONWebSignatureAndEncryptionAlgorithms::Dir
            )
        );

        $shared_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('shared_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::Dir);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($shared_key, $alg, $enc, $payload ));

        // and finally encrypt it ...
        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));

        $segments = explode('.',$compact_serialization);
        // key should be empty
        $this->assertTrue(empty($segments[1]));
    }


    public function testDecryptDir()
    {
        // Round-trip test: encrypt with DIR + A128CBC-HS256, then decrypt

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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt with DIR algorithm
        $shared_key =  OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                'this_is_a_secret_key_long_enough',
                JSONWebSignatureAndEncryptionAlgorithms::Dir
            )
        );

        $shared_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('shared_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::Dir);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($shared_key, $alg, $enc, $payload_jws));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Now decrypt
        $jwe_2 = JWEFactory::build
        (
            new JWE_CompactFormatSpecification
            (
                $jwe_compact_form
            )
        );

        $this->assertTrue(!is_null($jwe_2));

        $shared_key_2 = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                'this_is_a_secret_key_long_enough',
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $shared_key_2->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('shared_key');

        $jwe_2->setRecipientKey($shared_key_2);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_2));

        // Verify the inner JWS
        $jws_2 = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testCreateWithZip()
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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        // and sign the jws with server private key
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));

        $payload = $jws->toCompactSerialization();

        //load client public key
        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $zip     = new JsonValue(CompressionAlgorithmsNames::Deflate );
        $jwe     = JWEFactory::build( new JWE_ParamsSpecification($recipient_key, $alg, $enc, $payload, $zip ));

        // and finally encrypt it ...
        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));
    }

    public function testDecryptZipped()
    {
        // Round-trip test: encrypt with RSA1_5 + A256CBC-HS512 + DEF compression, then decrypt

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

        // load server key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt with compression
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $zip     = new JsonValue(CompressionAlgorithmsNames::Deflate);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws, $zip));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Now decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_2));

        // Verify the inner JWS
        $jws_2 = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testEncryptDecryptRSAOAEP()
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

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt the JWS as a JWE using RSA-OAEP + A256CBC-HS512
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        // Verify the inner JWS signature
        $jws_2 = JWSFactory::build(new JWS_CompactFormatSpecification($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );
        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testEncryptDecryptRSAOAEP256()
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

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt the JWS as a JWE using RSA-OAEP-256 + A256CBC-HS512
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP_256
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP_256);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        // Verify the inner JWS signature
        $jws_2 = JWSFactory::build(new JWS_CompactFormatSpecification($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );
        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testEncryptDecryptA192CBCHS384()
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

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt the JWS as a JWE using RSA1_5 + A192CBC-HS384
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A192CBC_HS384);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        // Verify the inner JWS signature
        $jws_2 = JWSFactory::build(new JWS_CompactFormatSpecification($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );
        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testEncryptDecryptGZipped()
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

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt with GZip compression
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $zip     = new JsonValue(CompressionAlgorithmsNames::GZip);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws, $zip));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_2));

        // Verify the inner JWS
        $jws_2 = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testEncryptDecryptZLib()
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

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));
        $payload_jws = $jws->toCompactSerialization();

        // Encrypt with ZLib compression
        $recipient_pub_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key2_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RSA1_5
            )
        );

        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $zip     = new JsonValue(CompressionAlgorithmsNames::ZLib);
        $jwe     = JWEFactory::build(new JWE_ParamsSpecification($recipient_pub_key, $alg, $enc, $payload_jws, $zip));
        $jwe_compact_form = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($jwe_compact_form));

        // Decrypt
        $jwe_2 = JWEFactory::build(new JWE_CompactFormatSpecification($jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $recipient_key = RSAJWKFactory::build
        (
            new RSAJWKPEMPrivateKeySpecification
            (
                TestKeys::$private_key2_pem,
                RSAJWKPEMPrivateKeySpecification::WithoutPassword,
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_2));

        // Verify the inner JWS
        $jws_2 = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws_2));

        $server_pub_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_pub_key->setId('rsa_server');
        $res = $jws_2->setKey($server_pub_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }

    public function testInvalidJWECompactFormat()
    {
        $this->expectException(JWEInvalidCompactFormatException::class);

        JWEFactory::build(new JWE_CompactFormatSpecification('a.b.c'));
    }
}
