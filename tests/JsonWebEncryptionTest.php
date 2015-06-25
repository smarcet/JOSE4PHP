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

/**
 * Class JsonWebEncryptionTest
 */
class JsonWebEncryptionTest extends PHPUnit_Framework_TestCase {


    public function testCreate(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        // load server key from pem format
        $server_key  = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));
        $server_key->setId('rsa_server');
        // and sign the jws with server private key
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));

        $payload = $jws->toCompactSerialization();

        //load client public key
        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build( new JWE_ParamsSpecification($recipient_key, $alg, $enc, $payload ));

        // and finally encrypt it ...
        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));
    }

    public function testDecrypt(){

        $payload_jws      = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InJzYV9zZXJ2ZXIiLCJqd2siOnsia3R5IjoiUlNBIiwiZSI6Ik5qVTFNemMiLCJuIjoiTVRjMU1UTTVPRGN6TnpJd05EZzJOek01TVRBeE9UQXhPRGt4TURFME1ESTROVGM1TnpBeU9ETTNPVEEwTkRrNU5EazNNelV5TXpReU1qUXhNell3T0RjNE5qVXhNakl6T1RrMk56azNOamN6TXpZd01qUTVNemcxTmpVME5UWTBNall4TWpRd09EZ3dNREEwT1RRNE1EQTNPREkyT1RFNU16TXhOVE0xTXpnek1EZ3lNVFkzTmprek5qZzVOVGM0TkRZeE5UUXpOREUyTkRVek1EVTBNVGN6TlRJNE9EZ3pNelkxT0RRd01UVTRNREF5TURjeE1qSXdNelkyT0RJeU9UQTROVE15TURneE1qYzFNekUwTkRZNU56VTVOalUwTmpVME56ZzJNRFUyTmpVM09UQTFOemcyT0RJeE5qa3hNRFkxTlRrNE1qUTNPVEUxTkRnMU5qRXlNamN6TWpBek5EYzBNRGMzTnpZd09UWXlOalUxT0RrMk56STRPRGcwT0RJMU9EZzVNRFV5TkRVek1EWXlPVGd5TmpjME1ETXlOVGc0T0RRMk5EWXlPVFl4TXpjd05qSTBPRGcwTlRFME9URTJPRGN4TWprek5USTJNekl4TkRBeU1EazFNekkzTWpBd09EUTBOakV5TVRNMU5EYzVPVE0yTmpFMk9EVTNNREkzTnpneU1qUTVOVGN4TlRNME5qSTVNakkxTXpFME9UazFOVEEyT0RBeE56YzRNVGd6TURrMU5UVTJPREkzTkRNd05Ea3dNekE0T1Rrek16TXdNall3T1RnNE5EYzVPRGt5TXprNU56a3dOekkwTWpFeE1Ea3hOakExT1RRek5UVXdNREk1TWpZME16VTBNemN5TlRNMU16QXhOVGd6TmpJMU1UWTJOVFV3TmpVME9EUXpORGc1TlRFMU9UZzNNalF4TlRReE5qY3pPRFF3TmpJME9ESTJNekkzTVRNMU9ERXlNelE0T0RjNU56STFOek16TWpFeU5EazFPRFF6TnpnNE5Ea3hNelU1TkRNM09ERTNOelV4TlRreU9EZzJPVEE1TlRRek16azNOek01T0RnNU56TSIsImFsZyI6IlJTMjU2IiwidXNlIjoic2lnIiwia2lkIjoicnNhX3NlcnZlciJ9fQ.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJzdWRvIiwiZGV2cyJdfQ.a8Huoaa7yQRykqqnR7w4MEIDTwN2o9QFUe1OX_IJdkAt-zqOYnWcWTzIAFwhCVPMFaS5G5CscoPKvZ9CObLptUQYI2BnWT_QKHyzD-5sMtYBQ76q09ih8NbTEJqsfgezxd48XSl_tkXY1X2Gw-pIbz_FZcpj05aS13JzubhHnXFg8OkI9gwuCn2Ygw3BNDBcqlFRU6FICshic73_MHVZ8SwaJG03mhBqpVjM-zSWz3lA1AJVLWrtpvolvvinxrd1FqF3zFqrmRscxtI1HAmigZOhYXJT0kPwSVvnDvzcQFMG6HaRUopUPJzVvZzefxJkMc_7CtJLnhDO_kF2Pb2nGg';
        $jwe_compact_form = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.R3CoJRQ1i2H0n-9x3S-J-12NtEP8SYpu2z1TDmO1Min-G3z9UcchJrq2LVCaubE45V5lhJIgqP-HcZ3iAzcvhvrnD6wX1fAHuOvl9CGHcmzIYwr_med8Kj6LjtGZCXu0pfOU7oXruv5ifcR6_VEwNFOJdIB0c3Gxih-AVGpfKUqa--cMudGb7HHhfojJGtt-NS36KOKK_QY7_1MDRpEH0VBmh0tNfjvGjpPoN7DjoIN34to19hrFsS9__dv97UuadDDDX3wF9bA-beQJi3npHqKvSrcgsWnlEyM3gwBtzXby70-1oaw3tazNGECWoIHFnxrKA-Gm7N4JOPoDdupRxQ.ROk2YlmsAs8.1_0HyPqYLod51wtd_ZvlQJgJOAVbPLk0XVoFkMaPfVWskKs0WYVsmW-L-t6PG13iFtBPzfb2wGGn5lCLpnx9Y39YLh0oom3iv59WcsRIc1wt5Zk94_MoL_-WwNqy1LOrNICZahinWkUEN0rpblKQo1VvUutEOhuYwm26ypNFEku1V2TYOVxLgJXv_RqE4G79_CCiAHvQYJ_T7JpSIImRy6-qEmQe2VQVzjoZKeWx64XZAIP6mRoRUKtO8CeiroiJvjl92oVkU8soYBzdcZofgibwoAWcWuzE5KTQnDMGBl89ZItJ67pnSz9HNy5xXqhKGNOLG-wQ2DTYR10Ac4zLz3VsAa6hVlrRg6kiX9R556a_nrY4WkUhcFx4eMSDSi87umbFdMesWjo6hfGv73sOLsLIM6mHshkOh6ftG6paWdgSEdV6UlIJYxGxnk3YuZVIsOFOVSdpXu-pmCPhz5Z6exP63aCoFwN4w8YlcGxHN5R6WIvgE3RFGHwZaJsaUkqgxkF_bCtb2i_6veu8AHcuFNyapJBKEQajNVv5Q4EY5SD-68_vfDqmfWc000qeWc9akMr-ZAvB5bRalVN-gj2NDWZZ3h48nO83ZLrpIou5wXUqbWVhM7s87ae07a1k_6n1K_EIqNQav8yVJbiSGhPIGDu5X-shbbzdbGIv_n8ynpq-FZC0NltN8uDcXmSN39f7c2x6mffshd_7UiYYsCWRibyb7LiFq2bGPG1yNC6SYZffj2bHHOT4eDUphQPV2odsnAKL-p10kl0vwQFV41CMCHoXGDGtcaJngUc-obALgZWEstTvnrUqarzzYzdkU4TQYhcGYKcRe74oHZiWIhmWkVyrFvXrAec1JsiwvCt0ijIfaz6vw7R66RIk-7CE0uK-h4fmJPthOE4V4K80-My0eBRaujUn-MCfFroSRMEb7csQCpigkK3fjPeBNwFWpYmf9xAVB20eLqIlSvDRV9z8E6g1eZmqucZ9xdCtkAJ5S4FRtDMT063kNzyelyTmLPmC_H5X7771EmHJz1FVcP1sVcoD6fPCi-dAh3FQ1JSLOPNM2R_whp_iWRmWixjxA31tloBfQrN8fdzzpIWlHYS0LXo4QwRbepmYVNTowHvbUVE0RYYpWvN5MaJgJwIBYTHnVePvjjyWJj-MeZ13AG6ZHI7koY1klnqB2Lqg7FW2JBL5Orc-A5XQQp0-z93k7NSgT7uZJd2s2X6vYDzK8e8zbQHiIBfjyz7LvVx_hzjVTz7sR9eUXpTlYR80bBGOgGHRl69jz2jHaugR3vQ4K9ZLMPIW8kSc-K31e-WYxFGxO3c4ch7AAfEeBsA-WMU-mdORiWPFQqZGHrHx9-7opeRVgbRgzAzCq7GagTDKkoousXKl3kMe0VcHT4fK9y4ia-bHiMvJeBsz7njHUObZTClZdMxS0S6BlB-qNN6OkRm1lGde-jc5tkKZTSKY-94zGKFLKNzCkIiKo4F3_xS3QvnQRuPKoLZyWoJGgJA6LUF8RyJzsTbs_BhgJEK5WHen5HIbtf0ygJWKxiOXzXtJcllLYffkuSVFC3fImPU3nEK8UyEfy8gVBKzFg_pOwKhSzOpRb4-nh_tOpAA_hTxf-Dlc-yn0aXMh1ruVD_m34QYz9zr7hXuyKf46Scwzy-QFuSD0icfuJemTP1YTFaVqDHAO6GDq4GBpMRt4KhOdp_jf8Max1-Jli8AweQBMcFtw0bfUbKC3dpP1Rv0prH51R5IjFJC9d0fg3REzamJe30wsWK-PVTQeqvBMGhYvwEBK6giuxHg6KfQJqb4rMEkqGiqtUhzSKszc9QrCKC8hMc5bIBe-bwCzIf3M1X9yd4xY9QxyJkzQzpcKhrFRX1-41_3pR3gHk7f3S90q9yTuP5RaN8_EFS0c96DBdgwLyhu1ThoVLpwDMdBwRwpbpbjz8nK-YDRVebgBftofT7IUKcawgZt377nR9OSm_vpBphguDqldxwqFCfKNa6pUdDuO3IN0mQuUgwE7hSCCV7EGT0QNvoWo0812Jb58MMXgZxHsSyLyfmSDpXI6j1hZXEY28Ig6xkyN-jCipOC96yw7u6fdeeUaCFR4uczqMh26-8ynwL1DC3cDLoFvII4uGAqXBl3fOUy_SOlYeJ4Q0YI5p0eqAK60SE2ioT-BBm2naFD7waHbcT1GenxxiNb4UnycSVfRiciKdpakVX5z2TVFkDBaiBxQDe-atdj0aNxgOR_9GSsXWt6mkuSaEHNjCxMO5B6Vqc4ZwdTycdZRaGXE4KClOAr3lQjbbclGPhSjXKeW8zxsDJeCw9fsUzsSei16Vhgf9A84o_HiwO0xcSAViwdhejE.aWwrSDRslzEix5j7yiDzgVwxpYhSJhkDLYqrMGVkwRM';

        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2 = JWEFactory::build( new JWE_CompactFormatSpecification( $jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        $jws = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_jws));

        $this->assertTrue(!is_null($jws));


        // load server public key from pem format
        $server_key  = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key_pem));
        $server_key->setId('rsa_server');
        // and verify signature.
        $res = $jws->setKey($server_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }


    public function testCreateWithZip(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        // load server key from pem format
        $server_key  = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key_pem));
        $server_key->setId('rsa_server');
        // and sign the jws with server private key
        $alg     = new StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RS384);
        $jws     = JWSFactory::build( new JWS_ParamsSpecification ( $server_key, $alg, $claim_set));

        $payload = $jws->toCompactSerialization();

        //load client public key
        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $zip     = new JsonValue(CompressionAlgorithmsNames::Deflate );
        $jwe     = JWEFactory::build( new JWE_ParamsSpecification($recipient_key, $alg, $enc, $payload, $zip ));

        // and finally encrypt it ...
        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));
    }

    public function testDecryptZipped(){

        $jwe_compact_form  = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiREVGIn0.d2WNqpFsibpyvLOmHNu9b1BtOFGF2JX5qFkPIldZ1p_hqBekEOx-JmyqmfLQrrXCosCUoyUWVuyKNmc268lMU1P3lSvuxs1qJYxx6jQ3xFJR3s9-qn0lFoE8_2y1DNE1fTIC2o23pm3HLECOyA952QKecrloGsQButaebmOPIam9w5iv2Yj6iJKVv0qMDGJUy7fzR-mdTCc-I1xfHuxgZSaQDc3KVFeDaWjLdtQBiYd1U3wivx7ozP9gbqlOUqOhQczOJAF8gsSUTDeXSTooWzlID_8dLoKem4WOQwS216r0xJKgjfPwvFJWMedia5tr9pTADfE6CPY1G5WF6jEhmQ.ZcnevEOrIXc._Xmy8Didgae56QzwHixlFomPBI0qP1z8c4XDoN-BghppXE88679oXjCfs7Ie_1RoKbJMdn-rKL0eaUlme1cypqEwaIvNoJAFhITFNzCya6XriEFkwA7FArHd31sO78XLXDXAYAm9Up-4F9Sbvzv8F_ZZloQqVICBqGLXDST45AqL2ZdS_sRJQn9lZG4VCjvncvrQeQkV8M60NiIF83FtJDaw7s5F5PewPUrDwZhHc3jiaFs7ioGzkrb7bYS_mvACmXIsd7Om13QPJQoZHH8LRC7Wuu51_quNQyMYmIDKG5qE6AVlUz-o9kyN8qwhun2NomVMb8fvOIPD6MTxVly39QjnN-p76pCclSaKw5Ox4wfGIcRU9PEPrRUVzvsRifBQFPIZHD3aWvayiNXC8jbeWj_tUm-9Be79r0jqGGkzNFudT8HAWvWBSWbpVzmhofXFjl7zzq4XGj-O7S8CendP49O-m-rnSlNqlKW22s2ug-Hdsnz52UENCIErvXLvFdyTAHnglSsI9fmA5Ze6_OKCLmJMxJDUK757PRcoAUpiM8DXS_7OQoaHnPbuYwCysKqx02TWNkBUvGO3mTcUGs0Xgxxrzdd9qcKWCLD_3d_8QN29LTWjx9Lj-ub6kHtAsG0JGffxg8MUripBaPrkYbA46DZGf5k5M1UBZqW9Kif1ByJ80w0Nn1JvTTidbuhTzFktiwiit0JzubfOBzwwCt9ZhrOWRKajAOnJiHYYiCqjMzKLFRMetupKDEiVT2qLOJMsYKLfc19srRg8Hos4C0uT2mHD3CL8Yllr7FgV2PRwIX6KSwJctVXhxraETfAWzUebgkwkwEyKpIjhKedAiOYqlr_TdNQOzNNWLsDgdVLc55A4aEdoGPvOO_VTeqbedSETtKt5ZL00OBHerXikabp97RxbWG7RNkuoGCdzSsY2Wakbb7g8SSjHyN0Wo2JBN2AE5YH9hUhEoIfjJARvOE2ZUy03uCv6MF0_Q_AVxeJtSPoFxw19VpX2VXxNnGrkT5ewrP2rm8GApaCemZidXTAzIYUvIdhrtGnRtP5oVC7YhvjhGX4Cegf27MFmQ00O2d-pJyiZnflrLpf58ORDDu7VUgLzrQfI1_Z_njssm2DGjV36mBXT7XbI5xxyk5xsq6fL9bXL_Gc7uoF_nacJSJgwh8mJ1Lc16fl95-SHRRKw6ffRvRnPq7JG2Hape-GVRA3MIZXHv4cIjeLTjYJmjHHtLx684co7SjxaDkwFQUYRE2Ho5QOl9A9juJWhVGd2o7txffIiOkFOhXLEOVqGOu6b4_-coWp1lSwqHqVQqbhYV6MsNvBrfxY72O9gVsScJ_D3tUbluHDvW9dYSjYR03NhE3qzaRGV7J6jz9rwOmWkBj96N-wpvzJik7BbWxvFJk2RbDbwQAJ7BgmBL55-AsHWJKNIn5YhqFlAb2P8xKLv_OCEfWmKzLptnh6981gN0VzCezqPJ0wpoe2xe7uZu6sPj4-GUqqMSPas4IzHNhMsQVV6RNM6ovOi33_uF4q_fqENMRkbS1i0npX3XoZbqE3hLw.2sNxwrV2hqnuQG3tUfzkNcLwX3cRUkcpZsNKWEuHIvg';

        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2 = JWEFactory::build( new JWE_CompactFormatSpecification( $jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_2));

        $jws = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws));

        $server_key  = RSAJWKFactory::build(new RSAJWKPEMPublicKeySpecification(TestKeys::$public_key_pem));
        $server_key->setId('rsa_server');
        // and verify signature.
        $res = $jws->setKey($server_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);

    }
}