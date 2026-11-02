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
use jwa\cryptographic_algorithms\ContentEncryptionAlgorithms_Registry;
use jwa\cryptographic_algorithms\exceptions\InvalidAuthenticationTagException;
use jwk\IJWK;
use utils\Base64UrlRepresentation;
use utils\ByteUtil;
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

    // ---------------------------------------------------------------------
    // Negative decrypt paths
    // ---------------------------------------------------------------------

    const DIR_SHARED_SECRET = 'this_is_a_secret_key_long_enough'; // 32 bytes = A128CBC-HS256 key size

    /**
     * @return IJWK
     */
    private static function dirSharedKey(): IJWK
    {
        $key = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                self::DIR_SHARED_SECRET,
                JSONWebSignatureAndEncryptionAlgorithms::Dir
            )
        );
        $key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('shared_key');
        return $key;
    }

    /**
     * dir + A128CBC-HS256 token for $plain_text
     * @param string $plain_text
     * @return string compact serialization
     */
    private static function encryptWithDir(string $plain_text): string
    {
        $alg = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::Dir);
        $enc = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256);
        $jwe = JWEFactory::build(new JWE_ParamsSpecification(self::dirSharedKey(), $alg, $enc, $plain_text));
        return $jwe->toCompactSerialization();
    }

    /**
     * @param string $compact
     * @param IJWK $recipient_key
     * @return string
     */
    private static function decrypt(string $compact, IJWK $recipient_key): string
    {
        $jwe = JWEFactory::build(new JWE_CompactFormatSpecification($compact));
        $jwe->setRecipientKey($recipient_key);
        return $jwe->getPlainText();
    }

    /**
     * Flips one bit in the first byte of the given compact-serialization segment
     * (0 header, 1 encrypted key, 2 iv, 3 ciphertext, 4 tag).
     * @param string $compact
     * @param int $segment
     * @return string
     */
    private static function tamperSegment(string $compact, int $segment): string
    {
        $b64   = new Base64UrlRepresentation();
        $parts = explode('.', $compact);
        $raw   = $b64->decode($parts[$segment]);
        $raw[0] = chr(ord($raw[0]) ^ 0x01);
        $parts[$segment] = $b64->encode($raw);
        return implode('.', $parts);
    }

    public function testDirRoundTripBaseline()
    {
        // guards the helpers used by the negative tests below
        $compact = self::encryptWithDir('hello');
        $this->assertEquals('hello', self::decrypt($compact, self::dirSharedKey()));
    }

    public function testTamperedTagIsRejected()
    {
        $this->expectException(InvalidAuthenticationTagException::class);

        $compact = self::tamperSegment(self::encryptWithDir('hello'), 4);
        self::decrypt($compact, self::dirSharedKey());
    }

    public function testTamperedCipherTextIsRejected()
    {
        $this->expectException(InvalidAuthenticationTagException::class);

        $compact = self::tamperSegment(self::encryptWithDir('hello'), 3);
        self::decrypt($compact, self::dirSharedKey());
    }

    public function testTamperedIVIsRejected()
    {
        // the IV is covered by the authentication tag (RFC 7518 §5.2.2.1)
        $this->expectException(InvalidAuthenticationTagException::class);

        $compact = self::tamperSegment(self::encryptWithDir('hello'), 2);
        self::decrypt($compact, self::dirSharedKey());
    }

    /**
     * @param string $alg
     * @return string compact serialization encrypted for TestKeys::$public_key2_pem
     */
    private static function encryptForKey2(string $alg): string
    {
        $recipient_pub_key = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key2_pem, $alg));
        $recipient_pub_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient');

        $jwe = JWEFactory::build(new JWE_ParamsSpecification
        (
            $recipient_pub_key,
            new StringOrURI($alg),
            new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256),
            'hello'
        ));
        return $jwe->toCompactSerialization();
    }

    /**
     * @param string $alg
     * @return IJWK TestKeys::$private_key_pem, which does NOT match $public_key2_pem
     */
    private static function wrongRecipientKey(string $alg): IJWK
    {
        $key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification
        (
            TestKeys::$private_key_pem,
            RSAJWKPEMPrivateKeySpecification::WithoutPassword,
            $alg
        ));
        $key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient');
        return $key;
    }

    public function testWrongRecipientKeyRSAOAEPThrows()
    {
        // phpseclib 3 surfaces an OAEP decoding failure as RuntimeException (see PR breaking changes)
        $this->expectException(\RuntimeException::class);

        $alg = JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP;
        self::decrypt(self::encryptForKey2($alg), self::wrongRecipientKey($alg));
    }

    public function testWrongRecipientKeyRSAOAEP256Throws()
    {
        $this->expectException(\RuntimeException::class);

        $alg = JSONWebSignatureAndEncryptionAlgorithms::RSA_OAEP_256;
        self::decrypt(self::encryptForKey2($alg), self::wrongRecipientKey($alg));
    }

    public function testWrongRecipientKeyRSA1_5Fails()
    {
        // RSA1_5 unwrap failure is either an InvalidAuthenticationTagException (OpenSSL >= 3.2
        // implicit rejection returns a random CEK, so the tag check fails) or phpseclib's own
        // RuntimeException('Decryption error'); either way no plaintext comes out.
        $alg = JSONWebSignatureAndEncryptionAlgorithms::RSA1_5;
        try {
            self::decrypt(self::encryptForKey2($alg), self::wrongRecipientKey($alg));
            $this->fail('decryption with the wrong key must not succeed');
        } catch (InvalidAuthenticationTagException | \RuntimeException $ex) {
            $this->assertTrue(true);
        }
    }

    public function testWrongLengthCEKIsRejectedAsBadTag()
    {
        // RFC 7516 §5.2 step 10 / §11.5: a CEK that is not exactly the size the enc
        // algorithm needs (what a failed RSA1_5 unwrap hands back) must end in the same
        // InvalidAuthenticationTagException as any other bad key, with no PHP notices
        // from splitting an odd-length key into float-sized halves.
        $enc = ContentEncryptionAlgorithms_Registry::getInstance()->get(JSONWebSignatureAndEncryptionAlgorithms::A128CBC_HS256);

        set_error_handler(function ($errno, $errstr, $errfile, $errline) {
            throw new \ErrorException($errstr, 0, $errno, $errfile, $errline);
        }, E_ALL);

        try {
            foreach ([31, 33, 64] as $wrong_len) {
                try {
                    $enc->decrypt(random_bytes(16), random_bytes($wrong_len), random_bytes(16), 'aad', random_bytes(16));
                    $this->fail(sprintf('a %d-byte CEK must not decrypt A128CBC-HS256', $wrong_len));
                } catch (InvalidAuthenticationTagException $ex) {
                    $this->assertTrue(true);
                }
            }
        } finally {
            restore_error_handler();
        }
    }

    public function testLegacyLongIVIsRejected()
    {
        // 2.x emitted a 32-byte IV for A128CBC-HS256 (IV size = key size). 3.x uses the
        // 128-bit IV RFC 7518 §5.2 requires and must reject the old tokens, even when
        // their tag is valid, instead of silently truncating the IV.
        $this->expectException(\LengthException::class);

        $b64 = new Base64UrlRepresentation();

        // reuse a genuine protected header so the token is otherwise well formed
        $header_b64 = explode('.', self::encryptWithDir('hello'))[0];

        $cek         = self::DIR_SHARED_SECRET;
        $mac_key     = substr($cek, 0, 16);
        $iv          = random_bytes(32);
        $cipher_text = random_bytes(16);
        $aad         = $header_b64;
        $al          = ByteUtil::convert2UnsignedLongBE(strlen($aad) * 8);
        // T = first 16 octets of HMAC-SHA256(MAC_KEY, A || IV || E || AL)
        $tag = substr(hash_hmac('sha256', $aad . $iv . $cipher_text . $al, $mac_key, true), 0, 16);

        $compact = implode('.', [
            $header_b64,
            '',
            $b64->encode($iv),
            $b64->encode($cipher_text),
            $b64->encode($tag),
        ]);

        self::decrypt($compact, self::dirSharedKey());
    }
}
