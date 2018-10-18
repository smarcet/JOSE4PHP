<?php namespace jwk\impl;
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
use jwa\cryptographic_algorithms\DigitalSignatures_MACs_Registry;
use jwa\cryptographic_algorithms\KeyManagementAlgorithms_Registry;
use jwk\exceptions\InvalidJWKAlgorithm;
use jwk\exceptions\JWKInvalidSpecException;
use jwk\IJWKSpecification;
use jwk\JSONWebKeyTypes;
use security\SymmetricSharedKey;
use \jwk\IJWK;
use utils\services\Utils_Registry;
/**
 * Class OctetSequenceJWKFactory
 * @package jwk\impl
 */
final class OctetSequenceJWKFactory
{

    /**
     * @param IJWKSpecification $spec
     * @return IJWK
     * @throws InvalidJWKAlgorithm
     * @throws JWKInvalidSpecException
     */
    static public function build(IJWKSpecification $spec)
    {

        if(is_null($spec)) throw new \InvalidArgumentException('missing spec param');

        $algorithm = DigitalSignatures_MACs_Registry::getInstance()->get
        (
            $spec->getAlg()
        );

        if(is_null($algorithm))
            $algorithm = ContentEncryptionAlgorithms_Registry::getInstance()->get
            (
                $spec->getAlg()
            );

        if(is_null($algorithm))
            $algorithm = KeyManagementAlgorithms_Registry::getInstance()->get
            (
                $spec->getAlg()
            );

        if(is_null($algorithm))
            throw new InvalidJWKAlgorithm
            (
                sprintf(
                    'alg %s not supported!',
                    $spec->getAlg()
                )
            );


        if($algorithm->getKeyType() !== JSONWebKeyTypes::OctetSequence)
            throw new InvalidJWKAlgorithm
            (
                sprintf
                (
                    'key type %s not supported!',
                    $algorithm->getKeyType()
                )
            );

        if(!($spec instanceof OctetSequenceJWKSpecification)) throw new JWKInvalidSpecException;

        $shared_secret = $spec->getSharedSecret();
        $secret_len    = strlen($shared_secret);

        if($secret_len === 0 )
        {
            $generator = Utils_Registry::getInstance()->get(Utils_Registry::RandomNumberGeneratorService);
            $shared_secret = $generator->invoke($algorithm->getMinKeyLen() / 8);
        }

        return OctetSequenceJWK::fromSecret
        (
            new SymmetricSharedKey
            (
                $shared_secret
            ),
            $spec->getAlg(),
            $spec->getUse()
        );
    }

}