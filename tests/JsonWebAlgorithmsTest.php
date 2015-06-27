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

use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A128CBCHS256_Algorithm;
use utils\ByteUtil;
use jwa\cryptographic_algorithms\exceptions\InvalidKeyLengthAlgorithmException;
use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A192CBCHS384_Algorithm;
use jwa\cryptographic_algorithms\content_encryption\AES_CBC_HS\sha2\A256CBCHS512_Algorithm;

/**
 * Class JsonWebAlgorithmsTest
 *
 * Test Cases for AES_CBC_HMAC_SHA2 Algorithms
 *
 */
final class JsonWebAlgorithmsTest extends PHPUnit_Framework_TestCase {

    /**
     * https://tools.ietf.org/html/rfc7518#appendix-B.1
     *
     * @throws InvalidKeyLengthAlgorithmException
     */
    public function testAES_128_CBC_HMAC_SHA_256(){

        $a   = new A128CBCHS256_Algorithm();

        $key = ByteUtil::convertOctArrayToBin( array(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ));

        $plain_text  = ByteUtil::convertOctArrayToBin( array (
            0x41 ,0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
            0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
            0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
            0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
            0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
            0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
            0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
        ));

        $iv = ByteUtil::convertOctArrayToBin( array(
            0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
         ));

        $aad = ByteUtil::convertOctArrayToBin(array(
            0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
            0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
            0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73
        ));

        list($cypher_text, $tag) =  $a->encrypt($plain_text, $key, $iv, $aad);


        $cypher_text_should =  ByteUtil::convertOctArrayToBin( array(
            0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83, 0x42, 0x79,
            0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54, 0xb9, 0x03, 0xa9, 0xc9,
            0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10, 0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2,
            0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14, 0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36,
            0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64, 0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8,
            0x6e, 0x13, 0x33, 0x14, 0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b,
            0x38, 0x4c, 0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
            0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27, 0xad, 0xe5,
            0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47, 0x3c, 0x82, 0xe2, 0xdb
        ));

        $tag_should =  ByteUtil::convertOctArrayToBin(array(0x65, 0x2c, 0x3f, 0xa3 ,0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19 , 0xfa, 0xb3, 0xa3, 0x0b, 0xc1, 0xc4));

        $this->assertTrue( $cypher_text == $cypher_text_should);

        $this->assertTrue( $tag == $tag_should);

    }

    /**
     * https://tools.ietf.org/html/rfc7518#appendix-B.2
     *
     * @throws InvalidKeyLengthAlgorithmException
     */
    public function testAES_192_CBC_HMAC_SHA_384(){

        $a = new A192CBCHS384_Algorithm;

        $key = ByteUtil::convertOctArrayToBin( array(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        ));

        $plain_text  = ByteUtil::convertOctArrayToBin( array (
            0x41 ,0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
            0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
            0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
            0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
            0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
            0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
            0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
        ));

        $iv = ByteUtil::convertOctArrayToBin( array(
            0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
        ));

        $aad = ByteUtil::convertOctArrayToBin(array(
            0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
            0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
            0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73
        ));

        list($cypher_text, $tag) =  $a->encrypt($plain_text, $key, $iv, $aad);


        $cypher_text_should =  ByteUtil::convertOctArrayToBin( array(
            0xea, 0x65, 0xda, 0x6b, 0x59, 0xe6, 0x1e, 0xdb, 0x41, 0x9b, 0xe6, 0x2d, 0x19, 0x71, 0x2a, 0xe5,
            0xd3, 0x03, 0xee, 0xb5, 0x00, 0x52, 0xd0, 0xdf, 0xd6, 0x69, 0x7f, 0x77, 0x22, 0x4c, 0x8e, 0xdb,
            0x00, 0x0d, 0x27, 0x9b, 0xdc, 0x14, 0xc1, 0x07, 0x26, 0x54, 0xbd, 0x30, 0x94, 0x42, 0x30, 0xc6,
            0x57, 0xbe, 0xd4, 0xca, 0x0c, 0x9f, 0x4a, 0x84, 0x66, 0xf2, 0x2b, 0x22, 0x6d, 0x17, 0x46, 0x21,
            0x4b, 0xf8, 0xcf, 0xc2, 0x40, 0x0a, 0xdd, 0x9f, 0x51, 0x26, 0xe4, 0x79, 0x66, 0x3f, 0xc9, 0x0b,
            0x3b, 0xed, 0x78, 0x7a, 0x2f, 0x0f, 0xfc, 0xbf, 0x39, 0x04, 0xbe, 0x2a, 0x64, 0x1d, 0x5c, 0x21,
            0x05, 0xbf, 0xe5, 0x91, 0xba, 0xe2, 0x3b, 0x1d, 0x74, 0x49, 0xe5, 0x32, 0xee, 0xf6, 0x0a, 0x9a,
            0xc8, 0xbb, 0x6c, 0x6b, 0x01, 0xd3, 0x5d, 0x49, 0x78, 0x7b, 0xcd, 0x57, 0xef, 0x48, 0x49, 0x27,
            0xf2, 0x80, 0xad, 0xc9, 0x1a, 0xc0, 0xc4, 0xe7, 0x9c, 0x7b, 0x11, 0xef, 0xc6, 0x00, 0x54, 0xe3,
        ));

        $tag_should =  ByteUtil::convertOctArrayToBin( array(
            0x84, 0x90, 0xac, 0x0e, 0x58, 0x94, 0x9b, 0xfe, 0x51, 0x87, 0x5d, 0x73,
            0x3f, 0x93, 0xac, 0x20, 0x75, 0x16, 0x80, 0x39, 0xcc, 0xc7, 0x33, 0xd7
        ));

        $this->assertTrue( $cypher_text == $cypher_text_should);

        $this->assertTrue( $tag == $tag_should);

    }

    /**
     * https://tools.ietf.org/html/rfc7518#appendix-B.3
     *
     * @throws InvalidKeyLengthAlgorithmException
     */
    public function testAES_256_CBC_HMAC_SHA_512(){

        $a = new A256CBCHS512_Algorithm;

        $key = ByteUtil::convertOctArrayToBin( array(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ));

        $plain_text  = ByteUtil::convertOctArrayToBin( array (
            0x41 ,0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
            0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
            0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
            0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
            0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
            0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
            0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
        ));

        $iv = ByteUtil::convertOctArrayToBin( array(
            0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
        ));

        $aad = ByteUtil::convertOctArrayToBin(array(
            0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
            0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
            0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73
        ));

        list($cypher_text, $tag) =  $a->encrypt($plain_text, $key, $iv, $aad);


        $cypher_text_should =  ByteUtil::convertOctArrayToBin( array(
            0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5, 0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
            0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26, 0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
            0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b, 0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
            0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07, 0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
            0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6, 0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
            0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b, 0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
            0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41, 0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
            0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53, 0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
            0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93, 0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6,
        ));

        $tag_should =  ByteUtil::convertOctArrayToBin( array(
            0x4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c, 0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
            0x2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d, 0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5,
        ));

        $this->assertTrue( $cypher_text == $cypher_text_should);

        $this->assertTrue( $tag == $tag_should);

    }

}