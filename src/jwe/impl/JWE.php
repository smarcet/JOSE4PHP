<?php namespace jwe\impl;
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
use jwa\cryptographic_algorithms\ContentEncryptionAlgorithms_Registry;
use jwa\cryptographic_algorithms\EncryptionAlgorithm;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyTypeAlgorithmException;
use jwa\cryptographic_algorithms\key_management\modes\DirectEncryption;
use jwa\cryptographic_algorithms\key_management\modes\DirectKeyAgreement;
use jwa\cryptographic_algorithms\key_management\modes\KeyAgreementWithKeyWrapping;
use jwa\cryptographic_algorithms\key_management\modes\KeyEncryption;
use jwa\cryptographic_algorithms\key_management\modes\KeyWrapping;
use jwa\cryptographic_algorithms\KeyManagementAlgorithms_Registry;
use jwe\exceptions\JWEInvalidCompactFormatException;
use jwe\exceptions\JWEInvalidRecipientKeyException;
use jwe\exceptions\JWEUnsupportedContentEncryptionAlgorithmException;
use jwe\exceptions\JWEUnsupportedKeyManagementAlgorithmException;
use jwe\compression_algorithms\CompressionAlgorithms_Registry;
use jwe\IJWEJOSEHeader;
use jwe\IJWE;
use jwe\KeyManagementModeValues;
use jwk\exceptions\InvalidJWKAlgorithm;
use jwk\IJWK;
use jwk\JSONWebKeyKeyOperationsValues;
use jws\IJWSPayloadRawSpec;
use jws\IJWSPayloadSpec;
use jws\payloads\JWSPayloadFactory;
use jwt\utils\JOSEHeaderSerializer;
use security\Key;
/**
 * Class JWE
 * @package jwe\impl
 * @access private
 */
final class JWE implements IJWE, IJWESnapshot
{

    /**
     * @var IJWK
     */
    private $jwk = null;

    /**
     * @var IJWSPayloadSpec
     */
    private $payload = null;

    /**
     * @var IJWEJOSEHeader
     */
    private $header;

    /**
     * @var Key
     */
    private $cek = null;

    /**
     * @var string
     */
    private $tag = null;

    /**
     * @var string
     */
    private $cipher_text = null;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var string
     */
    private $enc_cek = null;

    private $should_decrypt = false;

    /**
     * @param IJWEJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     */
    protected function __construct(IJWEJOSEHeader $header, IJWSPayloadSpec $payload = null)
    {
        $this->header = $header;
        if(!is_null($payload))
            $this->setPayload($payload);
    }

    /**
     * @param IJWK $recipient_key
     * @return $this
     */
    public function setRecipientKey(IJWK $recipient_key)
    {
        $this->jwk = $recipient_key;
        return $this;
    }

    /**
     * @param IJWSPayloadSpec $payload
     * @return $this
     */
    public function setPayload(IJWSPayloadSpec $payload)
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @param int $size
     * @return String
     */
    protected function createIV($size)
    {
        return IVFactory::build($size);
    }

    /**
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     * @return string
     */
    public function toCompactSerialization()
    {
        return JWESerializer::serialize($this->encrypt());
    }

    /**
     * @return mixed
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     */
    public function getPlainText()
    {
        if ($this->should_decrypt)
        {
            $this->decrypt();
        }

        if (is_null($this->payload))
            $this->payload = JWSPayloadFactory::build('');

        return ($this->payload instanceof IJWSPayloadRawSpec) ? $this->payload->getRaw():'';
    }

    /**
     * @return IJWEJOSEHeader
     */
    public function getJOSEHeader()
    {
        return $this->header;
    }


    /***
     * @param EncryptionAlgorithm $alg
     * @param Key $recipient_public_key
     * @return string
     */
     private function getJWEEncryptedKey(EncryptionAlgorithm $alg, Key $recipient_public_key)
     {
        /**
         * When Key Wrapping, Key Encryption, or Key Agreement with Key
         * Wrapping are employed, encrypt the CEK to the recipient and let
         * the result be the JWE Encrypted Key.
         */
         $key_management_mode = $this->getKeyManagementMode($alg);
         switch($key_management_mode){
             case KeyManagementModeValues::KeyEncryption:
             case KeyManagementModeValues::KeyWrapping:
             case KeyManagementModeValues::KeyAgreementWithKeyWrapping:
             {
                 return $alg->encrypt($recipient_public_key, $this->cek->getEncoded());
             }
             /**
              * When Direct Key Agreement or Direct Encryption are employed, let
              * the JWE Encrypted Key be the empty octet sequence.
              */
             default:
             return '';
         }
     }

    /**
     * Determine the Key Management Mode employed by the algorithm used
     * to determine the Content Encryption Key value.  (This is the
     * algorithm recorded in the "alg" (algorithm) Header Parameter of
     * the resulting JWE.)
     * @param EncryptionAlgorithm $alg
     * @return string
     */
    private function getKeyManagementMode(EncryptionAlgorithm $alg)
    {
        if($alg instanceof KeyEncryption)
            return KeyManagementModeValues::KeyEncryption;
        if($alg instanceof KeyWrapping)
            return KeyManagementModeValues::KeyWrapping;
        if($alg instanceof DirectKeyAgreement)
            return KeyManagementModeValues::DirectKeyAgreement;
        if($alg instanceof KeyAgreementWithKeyWrapping)
            return KeyManagementModeValues::KeyAgreementWithKeyWrapping;
        if($alg instanceof DirectEncryption)
            return KeyManagementModeValues::DirectEncryption;
    }

    /**
     * @return $this
     * @throws InvalidJWKAlgorithm
     * @throws InvalidKeyTypeAlgorithmException
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     * @throws \Exception
     */
    private function encrypt()
    {

        if (is_null($this->jwk))
            throw new JWEInvalidRecipientKeyException;

        if($this->jwk->getAlgorithm()->getValue()!== $this->header->getAlgorithm()->getString())
            throw new InvalidJWKAlgorithm
            (
                sprintf
                (
                    'mismatch between algorithm intended for use with the key %s and the cryptographic algorithm used to encrypt or determine the value of the CEK %s',
                    $this->jwk->getAlgorithm()->getValue(),
                    $this->header->getAlgorithm()->getString()
                )
            );

        $recipient_public_key     = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::EncryptContent);

        $key_management_algorithm = KeyManagementAlgorithms_Registry::getInstance()->get($this->header->getAlgorithm()->getString());

        if (is_null($key_management_algorithm))
            throw new JWEUnsupportedKeyManagementAlgorithmException(sprintf('alg %s', $this->header->getAlgorithm()->getString()));

        if($key_management_algorithm->getKeyType() !== $recipient_public_key->getAlgorithm())
            throw new InvalidKeyTypeAlgorithmException
            (
                sprintf
                (
                    'key should be for alg %s, %s instead.',
                    $key_management_algorithm->getKeyType(),
                    $recipient_public_key->getAlgorithm()
                )
            );

        $content_encryption_algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get
        (
            $this->header->getEncryptionAlgorithm()->getString()
        );

        if (is_null($content_encryption_algorithm))
            throw new JWEUnsupportedContentEncryptionAlgorithmException
            (
                sprintf
                (
                    'enc %s',
                    $this->header->getEncryptionAlgorithm()->getString()
                )
            );

        $key_management_mode = $this->getKeyManagementMode($key_management_algorithm);

        $this->cek     = ContentEncryptionKeyFactory::build
        (
            $recipient_public_key,
            $key_management_mode,
            $content_encryption_algorithm
        );

        $this->enc_cek = $this->getJWEEncryptedKey($key_management_algorithm, $recipient_public_key);

        /**
         * Generate a random JWE Initialization Vector of the correct size
         * for the content encryption algorithm (if required for the
         * algorithm); otherwise, let the JWE Initialization Vector be the
         * empty octet sequence.
         */
        $this->iv      = '';

        if (!is_null($iv_size = $content_encryption_algorithm->getIVSize()))
        {
            $this->iv = $this->createIV($iv_size);
        }
        // We encrypt the payload and get the tag
        $jwt_shared_protected_header = JOSEHeaderSerializer::serialize($this->header);

        $payload = ($this->payload instanceof IJWSPayloadRawSpec) ? $this->payload->getRaw():'';
        $zip     = $this->header->getCompressionAlgorithm();
        /**
         * If a "zip" parameter was included, compress the plaintext using
         * the specified compression algorithm and let M be the octet
         * sequence representing the compressed plaintext; otherwise, let M
         * be the octet sequence representing the plaintext.
         */
        if(!is_null($zip))
        {
            $compression__algorithm = CompressionAlgorithms_Registry::getInstance()->get($zip->getValue());
            $payload  = $compression__algorithm->compress($payload);
        }

        /**
         * Encrypt M using the CEK, the JWE Initialization Vector, and the
         * Additional Authenticated Data value using the specified content
         * encryption algorithm to create the JWE Ciphertext value and the
         * JWE Authentication Tag (which is the Authentication Tag output
         * from the encryption operation).
         */
        list($this->cipher_text, $this->tag) = $content_encryption_algorithm->encrypt
        (
            $payload,
            $this->cek->getEncoded(),
            $this->iv,
            $jwt_shared_protected_header
        );

        return $this;
    }


    /**
     * @param EncryptionAlgorithm $alg
     * @return null|Key
     * @throws JWEInvalidCompactFormatException
     * @throws InvalidKeyTypeAlgorithmException
     * @throws \Exception
     */
    private function decryptJWEEncryptedKey(EncryptionAlgorithm $alg){

        $key_management_mode   = $this->getKeyManagementMode($alg);
        $recipient_private_key = $this->jwk->getKey(JSONWebKeyKeyOperationsValues::DecryptContentAndValidateDecryption);

        if($alg->getKeyType() !== $recipient_private_key->getAlgorithm())
            throw new InvalidKeyTypeAlgorithmException
            (
                sprintf
                (
                    'key should be for alg %s, %s instead.',
                    $alg->getKeyType(),
                    $recipient_private_key->getAlgorithm()
                )
            );

        switch($key_management_mode){
            /**
             * When Key Wrapping, Key Encryption, or Key Agreement with Key
             * Wrapping are employed, decrypt the JWE Encrypted Key to produce
             * the CEK.  The CEK MUST have a length equal to that required for
             * the content encryption algorithm
             */
            case KeyManagementModeValues::KeyEncryption:
            case KeyManagementModeValues::KeyWrapping:
            case KeyManagementModeValues::KeyAgreementWithKeyWrapping:
            {

                return ContentEncryptionKeyFactory::fromRaw($alg->decrypt($recipient_private_key, $this->enc_cek), $alg);
            }
            /**
             * When Direct Key Agreement or Direct Encryption are employed,
             * verify that the JWE Encrypted Key value is an empty octetsequence.
             * When Direct Encryption is employed, let the CEK be the shared
             * symmetric key.
             */
            case KeyManagementModeValues::DirectEncryption:
            {
                if (!empty($this->enc_cek))
                    throw new JWEInvalidCompactFormatException('JWE Encrypted Key value is not an empty octetsequence.');
                return $recipient_private_key;
            }
            case KeyManagementModeValues::DirectKeyAgreement:
            {
                if (!empty($this->enc_cek))
                    throw new JWEInvalidCompactFormatException('JWE Encrypted Key value is not an empty octetsequence.');
                throw new \Exception('unsupported Key Management Mode!');
            }
        }
        return null;
    }

    /**
     * @return $this
     * @throws InvalidJWKAlgorithm
     * @throws InvalidKeyTypeAlgorithmException
     * @throws JWEInvalidCompactFormatException
     * @throws JWEInvalidRecipientKeyException
     * @throws JWEUnsupportedContentEncryptionAlgorithmException
     * @throws JWEUnsupportedKeyManagementAlgorithmException
     * @throws \Exception
     */
    private function decrypt()
    {
        if (is_null($this->jwk))
            throw new JWEInvalidRecipientKeyException();

        if (!$this->should_decrypt) return $this;

        if($this->jwk->getAlgorithm()->getValue()!== $this->header->getAlgorithm()->getString())
            throw new InvalidJWKAlgorithm
            (
                sprintf
                (
                    'mismatch between algorithm intended for use with the key %s and the cryptographic algorithm used to encrypt or determine the value of the CEK %s',
                    $this->jwk->getAlgorithm()->getValue(),
                    $this->header->getAlgorithm()->getString()
                )
            );

        $key_management_algorithm = KeyManagementAlgorithms_Registry::getInstance()->get
        (
            $this->header->getAlgorithm()->getString()
        );

        if (is_null($key_management_algorithm))
            throw new JWEUnsupportedKeyManagementAlgorithmException
            (
                sprintf
                (
                    'alg %s',
                    $this->header->getAlgorithm()->getString()
                )
            );

        $content_encryption_algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get
        (
            $this->header->getEncryptionAlgorithm()->getString()
        );

        if (is_null($content_encryption_algorithm))
            throw new JWEUnsupportedContentEncryptionAlgorithmException
            (
                sprintf
                (
                    'enc %s',
                    $this->header->getEncryptionAlgorithm()->getString()
                )
            );

        $this->cek = $this->decryptJWEEncryptedKey($key_management_algorithm);

        // We encrypt the payload and get the tag
        $jwt_shared_protected_header = JOSEHeaderSerializer::serialize($this->header);

        /**
         * Decrypt the JWE Cipher Text using the CEK, the JWE Initialization
         * Vector, the Additional Authenticated Data value, and the JWE
         * Authentication Tag (which is the Authentication Tag input to the
         * calculation) using the specified content encryption algorithm,
         * returning the decrypted plaintext and validating the JWE
         * Authentication Tag in the manner specified for the algorithm,
         * rejecting the input without emitting any decrypted output if the
         * JWE Authentication Tag is incorrect.
         */
        $plain_text = $content_encryption_algorithm->decrypt
        (
            $this->cipher_text,
            $this->cek->getEncoded(),
            $this->iv,
            $jwt_shared_protected_header,
            $this->tag
        );

        $zip     = $this->header->getCompressionAlgorithm();
        /**
         * If a "zip" parameter was included, uncompress the decrypted
         * plaintext using the specified compression algorithm.
         */
        if(!is_null($zip))
        {
            $compression__algorithm = CompressionAlgorithms_Registry::getInstance()->get($zip->getValue());
            $plain_text = $compression__algorithm->uncompress($plain_text);
        }

        $this->setPayload(JWSPayloadFactory::build($plain_text));
        $this->should_decrypt = false;

        return $this;
    }

    /**
     * @return array
     */
    public function take()
    {
        return array(
            $this->header,
            $this->enc_cek,
            $this->iv,
            $this->cipher_text,
            $this->tag);
    }

    /**
     * @param IJWEJOSEHeader $header
     * @param IJWSPayloadSpec $payload
     * @return IJWE
     */
    public static function fromHeaderAndPayload(IJWEJOSEHeader $header, IJWSPayloadSpec $payload)
    {
        return new JWE($header, $payload);
    }

    /**
     * @param string $compact_serialization
     * @return IJWE
     * @throws JWEInvalidCompactFormatException
     * @access private
     */
    public static function fromCompactSerialization($compact_serialization)
    {
        list($header, $enc_cek, $iv, $cipher_text, $tag) = JWESerializer::deserialize($compact_serialization);
        $jwe = new JWE($header);
        $jwe->iv = $iv;
        $jwe->tag = $tag;
        $jwe->enc_cek = $enc_cek;
        $jwe->cipher_text = $cipher_text;
        $jwe->should_decrypt = true;
        return $jwe;
    }
}