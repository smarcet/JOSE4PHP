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
/**
 * Class JsonWebEncryptionTest
 */
final class JsonWebEncryptionTest extends PHPUnit_Framework_TestCase
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

        $payload_jws      = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InJzYV9zZXJ2ZXIiLCJqd2siOnsia3R5IjoiUlNBIiwiZSI6Ik5qVTFNemMiLCJuIjoiTVRjMU1UTTVPRGN6TnpJd05EZzJOek01TVRBeE9UQXhPRGt4TURFME1ESTROVGM1TnpBeU9ETTNPVEEwTkRrNU5EazNNelV5TXpReU1qUXhNell3T0RjNE5qVXhNakl6T1RrMk56azNOamN6TXpZd01qUTVNemcxTmpVME5UWTBNall4TWpRd09EZ3dNREEwT1RRNE1EQTNPREkyT1RFNU16TXhOVE0xTXpnek1EZ3lNVFkzTmprek5qZzVOVGM0TkRZeE5UUXpOREUyTkRVek1EVTBNVGN6TlRJNE9EZ3pNelkxT0RRd01UVTRNREF5TURjeE1qSXdNelkyT0RJeU9UQTROVE15TURneE1qYzFNekUwTkRZNU56VTVOalUwTmpVME56ZzJNRFUyTmpVM09UQTFOemcyT0RJeE5qa3hNRFkxTlRrNE1qUTNPVEUxTkRnMU5qRXlNamN6TWpBek5EYzBNRGMzTnpZd09UWXlOalUxT0RrMk56STRPRGcwT0RJMU9EZzVNRFV5TkRVek1EWXlPVGd5TmpjME1ETXlOVGc0T0RRMk5EWXlPVFl4TXpjd05qSTBPRGcwTlRFME9URTJPRGN4TWprek5USTJNekl4TkRBeU1EazFNekkzTWpBd09EUTBOakV5TVRNMU5EYzVPVE0yTmpFMk9EVTNNREkzTnpneU1qUTVOVGN4TlRNME5qSTVNakkxTXpFME9UazFOVEEyT0RBeE56YzRNVGd6TURrMU5UVTJPREkzTkRNd05Ea3dNekE0T1Rrek16TXdNall3T1RnNE5EYzVPRGt5TXprNU56a3dOekkwTWpFeE1Ea3hOakExT1RRek5UVXdNREk1TWpZME16VTBNemN5TlRNMU16QXhOVGd6TmpJMU1UWTJOVFV3TmpVME9EUXpORGc1TlRFMU9UZzNNalF4TlRReE5qY3pPRFF3TmpJME9ESTJNekkzTVRNMU9ERXlNelE0T0RjNU56STFOek16TWpFeU5EazFPRFF6TnpnNE5Ea3hNelU1TkRNM09ERTNOelV4TlRreU9EZzJPVEE1TlRRek16azNOek01T0RnNU56TSIsImFsZyI6IlJTMjU2IiwidXNlIjoic2lnIiwia2lkIjoicnNhX3NlcnZlciJ9fQ.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJzdWRvIiwiZGV2cyJdfQ.a8Huoaa7yQRykqqnR7w4MEIDTwN2o9QFUe1OX_IJdkAt-zqOYnWcWTzIAFwhCVPMFaS5G5CscoPKvZ9CObLptUQYI2BnWT_QKHyzD-5sMtYBQ76q09ih8NbTEJqsfgezxd48XSl_tkXY1X2Gw-pIbz_FZcpj05aS13JzubhHnXFg8OkI9gwuCn2Ygw3BNDBcqlFRU6FICshic73_MHVZ8SwaJG03mhBqpVjM-zSWz3lA1AJVLWrtpvolvvinxrd1FqF3zFqrmRscxtI1HAmigZOhYXJT0kPwSVvnDvzcQFMG6HaRUopUPJzVvZzefxJkMc_7CtJLnhDO_kF2Pb2nGg';
        $jwe_compact_form = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.QsuGdnlMU4koqOkEXn-pJOjq-qsdVjMas_324HoUJgmPTNvL7Q6JNb2sa62rPp2oCumhXiPXss2HkvPKrEsy1WxrAaJtzKKMp_bl65IUe4l7eiHX0TbUiUoCpsacJa7K7L_vY4uEb5nr6sZ8IsdaW9mlJNrQf_dlq18rl6RoIKkGsHU7cNPxw-V7WtFWJjgMdDBJ2MJw050DLQrA217r7HuahLvts1lHUWLOXkiLpThYr0K2iV4mXouODcz8c90jTh-gCUz1yjwGajpeMwUovabPjPAQKhaOjHaoxaRBh1SD2DTnhvbtEPaxuRxvKEiM7uf3t3qBm1vs4Tjjma2PNSHf-iEJEUkUMVl10PPZ0Q4smS622KgcG371_JAjdBMn614gB2x8FBV_0y6EAc1DHF4Lxrpo4B2yw8WOdsS9ooUFakXRulcpAj4DYfL4ZJphzC7tXbrIX6vq-yo1a-nPAAGY87hkQow1nSoYUSeSVvEDFZD0MVzuSXE1btVZJfnHd8mjDEFTLxfqrCWZxC5jhzdGcGnBFOV3Gzt3obvn20iS-8jds3LVe4to28aSOX_jGUJjxXRQXRCzVuy9kUeHfrX56gKIp8IEaeQQP4Cr9cyXsbrS5WvUw8dmZjPLvC_t_pb5dHFeDK7gE3rPKlNgsjecfhlgmdp7Tve3Evee83Q.uIUD3haEyB45qWTbY-3txWWlDUX3XA8cVwonOYoX_543hxqSHkegWZ3IgU4PhcAFcHB3RFackjw6C4ZnbIGQvw.DeSYoiSvZ5YvXrnWc90XVwWDmUvfYZgdAcx2x4Y5CTSRPEIuZTnOoTGrsHZDg25hlTPXfE8w2z4LFc1_OYVIBlDZ82p3-doMZqr6k0fiR_J3TJV2oRzs10gZveWbqHGTQRZ3TE7IOJtJ-dh_saO4R_IcZG_FwIq_d9YHHXBv2Bd8yEA7U7e1LBZA_CFYryQz2RHjaEnxVhwpKXkBId26MUS7eOBUhJ9yie0kEB-E6Rd7a6gvMxItM7feoe23M1069Ydt8UEqbtls4l496Qus61nxE0g5VZuhpQmR_CFRjQhgrKjyZPLQit2gmwt8yk_Ow7fzHK0TVxUe40TV6Nzf-9XueLhFbRc_KKyey10LDwX_QSijYS8keKcu3s84DHTapujLO7x3CAZ6VzdKYvMBkm_KtHyIU4V6UbT_uX3RtDIfQDhJ7XRrz8Zg9sEtctt3kSdUAKkvvlANOAsqK4Z-9nNCFP2IfYlR5LXFofzVtxZCMMLYCymB-1KmKwLEXDTWcooVAT2cC0nDX6IlYT3r3-VcNIuquJwji_yxDvcszziSdTMIlExrYXSDwDc2z-jvXCu11iZJ5u3MscVgTXypPUkrGAhIvdl6lQTWhtdwuKvcPBZbrOeAJq-tHnC0Sr49wecEmpaGvq3UCRTqYgzR-u9DEEzlMa_d54Y64ilOXWblBc3JcxblnQuO9tGBqVis1KwZ1CYLlYC2gye6BpPkYR73_tueisOKciaZIBYEDYhfow5PFFS1rQZFDu6Iq04S43IXvGg9k7JWv3d5cE1iqmMzMehZ7hf4_2gbF05s02y4HLxoooP7r6tekOAMcPkBCSqEqW04g993QhbOwCDnn2H_I-9YavdBknuDopVxcGQPydih-nJaID50rmAcszUCX5mIyMt3LMzJH6WdDhw__3kl2PeQO0hKCiTSDfdFVxJb0m7vdCFMFKOlpC1GneYU7x1YWEbulru57g4wmjkkmEO9G6oQPn-1SmCRQb5r16TH2_cYQsbCKFHeZxLWugcbUcnXZKdIVKre8icNUFQjjxypjJw6pNkXHzRXP6jvvfxmudsRuq6LB6VyiuMlmnuafqf55XlJLU9wQJGbj86-sUIpqW9o8YaYZSsFhgiwT6ETSOhJRRA91GDyhjJzjaskf3Grr0PGtWNv2fHBJyT469RspK6lQuCNhOGg4yd7itGoMT61sqxdYWVp8qMcBz1NPb0dQ93ibCRtPZO5GkUSOsLJHsu9axtB0DYICbCZwayjal-4FY6Tm-feuP84bqZEQy--vYogJ48DWEm_HOV-7Ihx3ibrVLahpn773HvS4QK8X6ifLbWhum563-hXBNc_6TK0BWBcQXJbDkVGlaiA4qAhczMnMifCzTLwLOjvbvaKl4rPTjdZr-uS-MgRzTIZK6U7MDZOMlYedj1jhmKROP0h7eQapIhugguKuILAdyy_36ckq-GSNpgolqI4m3AfIRxlUAo5nMECy8rSRtCusT90OhPbwR01Vr_tUze4-eot9sqquy85kAi8AtiwknLF_KKUnyNDS8dT8GzHbMilJK3OvL0P6iLyDBRpaGQ3Sb8YDKJBmSQvxGlqdxzTeAw4QMLJCogPkuT4vGsg6b6RomrX1UhtM6T03ia1qR8WMvrpRhwJPQCbG0vTEmaKMJiJ4YKmnGPPLJ7zClZ_OxYoDr-DXk10A-jHAJ-8xX-l88dD-cgYlyOvT6GZxjjvx9Qmzr3WJsFSA2U2gC5sHqrHzD-vUky9I7WFHieOpUW3_hM_-ypZDfWJnn7ehNi8te-EbUUSlhYmn_GoygalbCdx0zvVpZlzZsCEYjvOlU9ZdKFST2BPbjpRKppLhLUnlWHH7-KpP3elyiJy2GJcY1N0JY4LP3ZTJyCI_CVTeNDDbZHUdMD3v-oO78wu4DAK_XgVX_-rCOrt1pFZ_k-FONSVq8zQtts6LVeWcaX60Q-zc4jGvZ7bn88UuNNtiBuq3jzskSgI0jS185-EZd5gBM_ahkcEHnkEVk4DLC6fnKp5V3Cek8xEw7p_ADsVx-cNPR46T3JIblOQil_u4I8gh-w1S9R7J_5QVFDsFsdRWy-yzI2fmzbw7DUsysNUqXPXyFKnUOUFjTAIhiYtLKsXx2YO8l5Dj2P9lLgEkwGq3oxlf7vVG29A1iVtcKtyLqah5hMvi7Dp445jvHzHQmvb7Psi0Yy8_PjepEP0pWZ982NBn75Fx9D04FqBIoHvsAg0hVhykOMoBEdCA8GHzMP8zUDXeH7Gj6QeTYmRL0Q7JLdPxQUGsPyiwPCo9Q-5SirIJpDZjDwtH6_vZ_BrB_kWQSSWdDvd2okqpqaynVhlSutJdyU.pO_I4zL-ky1p1OQPd1Ta2bAV3kpcdOjrvY1whQ7-7Q6kuA-iaVkIoHilDhCslp6_PZ_wdTun96yG8JxQfH56AA';

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

        $jws = JWSFactory::build
        (
            new JWS_CompactFormatSpecification
            (
                $payload_jws
            )
        );

        $this->assertTrue(!is_null($jws));

        // load server public key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );
        $server_key->setId('rsa_server');
        // and verify signature.
        $res = $jws->setKey($server_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

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

        $jwe_compact_form = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..Z0rVzErM4afxeyjYdxsg-z9g00G3oDsQKX0l8sTtSes.JJWRYo7YYy606qdg-Z2QcLe7mvg_k6MmXU5OjBOVG-lGySJMyy2i6zxqxFtikVWmghwloq-ABXgpPDOsXUz5KwiI1C1dYeG52lmkf0fTjjI5mV6waaZrNI42Ii4EEZTJm0PMJz-ElbqBGJUlwsmoIIEHPeI6nXT3wXwgrtcYf8-eDsr0W869GiPCylLxrecWzc8bD5Dlvpnmy9cIUKnm6WJIcLMbouuaHSC4BRS_nqV2aqHoLvqPNS17cshyFRiy7m8rWdr8cGWjD5HpJQclpm9hkdH6WvOg5JEHjKYaSByC4goGzst4CQ9BsC_PPF1Fq4PdI1OmhzIo0xPwCyOx9WmKM4SL8v3vD9WdsgBbeYTs1h67GSdiydF3Bc9F_lCy6CwQYMMGmgrxJxosUXR10gb7kkVRbj2pc18CP1wgGJg2YIiskDenOwO3jss9NXjKycRm9rTWqvm7PVtD_XPAcZV-a0OttxIT0Y05A2eDT4YjiRu-5Re7LQgh7HknPn_k39MXypyOqC7vcJajUa9UsaR9nvJMV7LgcDFSYQRYF9iURKAvhXQMoPeT5xhuAoQMAnWtjFV0HqSlFysxBr0YbqLnkUm8NGrVle9G2HyxCDtFVdgakoQ-06zKFvswLS7-prxMmE_qfx_mMMPSm4Nv-dqXMcqiqmcTSNQqjHvBxGGiY30gLl_41RJRh68bI7zWZZrCLibXcV45VTU6w2v5xCk_cqHC00qOK_5GYtrlPgDPVOXpIwQ5lQtgEwWu8PeLqGRMmHS0MjKdFX9SdFNkjDd5ykVHg44y1L0H5ztCc7xlaC-xXKOJe-T2AMzOA9pO3eyzV5TbAGRpkSiiypo1RqVFSkXGjNrCmtK5Haha3jZxF3PsW9ZsB9aY0fcll0N0MqstVudgjovcdwaJs5nlu_NlT2Bm8mW4l30GHgjAoIYvbyGp0t43uFirUOGdxAmq1g1Q_hWs3CiGswsLBMkzk4rMMEuEGjACdjGGyK9Cxd4SzwlDWi7e0o5ALCaQoC7ZVjQrnc34MPYrDp1vQMhkPYq6-NwHWnNYLAtxYBOlq1-kc4qhtK7q03UiUstPsqqgwzM5sgkLraXrONkgibLG5nx0rHg8z3AOLuQ50xDURFZRqB9EAuqtHoorVsRHFf-j55kkxqksbwkx3_ReD3M3SkFh0vwK-aHxro5iAv0scLQOJawOzP_Bpx3JV0F91SCZr0rny1bvobCZE_U38BWZvTh5h3L9Gf2IMxPgVcHDYB9I4C4N9i3uKvFMdEqozJ26MmKrFyPQq60OX8WRb7QLesTCI8fcMepFuDonlqLdtOsj31u1wnxnAGvkQw4N08Iupe6MZEraWpKIRM9AGhKWRxgy1fLJscYbm3_yK5VF_gUSjTqe_OXSfnCQeqCuEzh8OlmAR7jGgCWAkBVQ9bhPo3MBnr_cJmcaeBqFzSW0GiQ7E-_22b0ak6f3RtLmd3HI.fwqQhABaFMFi-suUuhNPrw';


        $jwe_2 = JWEFactory::build
        (
            new JWE_CompactFormatSpecification
            (
                $jwe_compact_form
            )
        );

        $this->assertTrue(!is_null($jwe_2));

        //load shared key
        $shared_key = OctetSequenceJWKFactory::build
        (
            new OctetSequenceJWKSpecification
            (
                'this_is_a_secret_key_long_enough',
                $jwe_2->getJOSEHeader()->getAlgorithm()->getString()
            )
        );

        $shared_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('shared_key');

        $jwe_2->setRecipientKey($shared_key);

        $payload_jws = $jwe_2->getPlainText();

        $this->assertTrue(!empty($payload_jws));

        $jws = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_jws));

        $this->assertTrue(!is_null($jws));

        // load server public key from pem format
        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        // and verify signature.
        $res = $jws->setKey($server_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

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

        $jwe_compact_form  = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.QsuGdnlMU4koqOkEXn-pJOjq-qsdVjMas_324HoUJgmPTNvL7Q6JNb2sa62rPp2oCumhXiPXss2HkvPKrEsy1WxrAaJtzKKMp_bl65IUe4l7eiHX0TbUiUoCpsacJa7K7L_vY4uEb5nr6sZ8IsdaW9mlJNrQf_dlq18rl6RoIKkGsHU7cNPxw-V7WtFWJjgMdDBJ2MJw050DLQrA217r7HuahLvts1lHUWLOXkiLpThYr0K2iV4mXouODcz8c90jTh-gCUz1yjwGajpeMwUovabPjPAQKhaOjHaoxaRBh1SD2DTnhvbtEPaxuRxvKEiM7uf3t3qBm1vs4Tjjma2PNSHf-iEJEUkUMVl10PPZ0Q4smS622KgcG371_JAjdBMn614gB2x8FBV_0y6EAc1DHF4Lxrpo4B2yw8WOdsS9ooUFakXRulcpAj4DYfL4ZJphzC7tXbrIX6vq-yo1a-nPAAGY87hkQow1nSoYUSeSVvEDFZD0MVzuSXE1btVZJfnHd8mjDEFTLxfqrCWZxC5jhzdGcGnBFOV3Gzt3obvn20iS-8jds3LVe4to28aSOX_jGUJjxXRQXRCzVuy9kUeHfrX56gKIp8IEaeQQP4Cr9cyXsbrS5WvUw8dmZjPLvC_t_pb5dHFeDK7gE3rPKlNgsjecfhlgmdp7Tve3Evee83Q.uIUD3haEyB45qWTbY-3txWWlDUX3XA8cVwonOYoX_543hxqSHkegWZ3IgU4PhcAFcHB3RFackjw6C4ZnbIGQvw.DeSYoiSvZ5YvXrnWc90XVwWDmUvfYZgdAcx2x4Y5CTSRPEIuZTnOoTGrsHZDg25hlTPXfE8w2z4LFc1_OYVIBlDZ82p3-doMZqr6k0fiR_J3TJV2oRzs10gZveWbqHGTQRZ3TE7IOJtJ-dh_saO4R_IcZG_FwIq_d9YHHXBv2Bd8yEA7U7e1LBZA_CFYryQz2RHjaEnxVhwpKXkBId26MUS7eOBUhJ9yie0kEB-E6Rd7a6gvMxItM7feoe23M1069Ydt8UEqbtls4l496Qus61nxE0g5VZuhpQmR_CFRjQhgrKjyZPLQit2gmwt8yk_Ow7fzHK0TVxUe40TV6Nzf-9XueLhFbRc_KKyey10LDwX_QSijYS8keKcu3s84DHTapujLO7x3CAZ6VzdKYvMBkm_KtHyIU4V6UbT_uX3RtDIfQDhJ7XRrz8Zg9sEtctt3kSdUAKkvvlANOAsqK4Z-9nNCFP2IfYlR5LXFofzVtxZCMMLYCymB-1KmKwLEXDTWcooVAT2cC0nDX6IlYT3r3-VcNIuquJwji_yxDvcszziSdTMIlExrYXSDwDc2z-jvXCu11iZJ5u3MscVgTXypPUkrGAhIvdl6lQTWhtdwuKvcPBZbrOeAJq-tHnC0Sr49wecEmpaGvq3UCRTqYgzR-u9DEEzlMa_d54Y64ilOXWblBc3JcxblnQuO9tGBqVis1KwZ1CYLlYC2gye6BpPkYR73_tueisOKciaZIBYEDYhfow5PFFS1rQZFDu6Iq04S43IXvGg9k7JWv3d5cE1iqmMzMehZ7hf4_2gbF05s02y4HLxoooP7r6tekOAMcPkBCSqEqW04g993QhbOwCDnn2H_I-9YavdBknuDopVxcGQPydih-nJaID50rmAcszUCX5mIyMt3LMzJH6WdDhw__3kl2PeQO0hKCiTSDfdFVxJb0m7vdCFMFKOlpC1GneYU7x1YWEbulru57g4wmjkkmEO9G6oQPn-1SmCRQb5r16TH2_cYQsbCKFHeZxLWugcbUcnXZKdIVKre8icNUFQjjxypjJw6pNkXHzRXP6jvvfxmudsRuq6LB6VyiuMlmnuafqf55XlJLU9wQJGbj86-sUIpqW9o8YaYZSsFhgiwT6ETSOhJRRA91GDyhjJzjaskf3Grr0PGtWNv2fHBJyT469RspK6lQuCNhOGg4yd7itGoMT61sqxdYWVp8qMcBz1NPb0dQ93ibCRtPZO5GkUSOsLJHsu9axtB0DYICbCZwayjal-4FY6Tm-feuP84bqZEQy--vYogJ48DWEm_HOV-7Ihx3ibrVLahpn773HvS4QK8X6ifLbWhum563-hXBNc_6TK0BWBcQXJbDkVGlaiA4qAhczMnMifCzTLwLOjvbvaKl4rPTjdZr-uS-MgRzTIZK6U7MDZOMlYedj1jhmKROP0h7eQapIhugguKuILAdyy_36ckq-GSNpgolqI4m3AfIRxlUAo5nMECy8rSRtCusT90OhPbwR01Vr_tUze4-eot9sqquy85kAi8AtiwknLF_KKUnyNDS8dT8GzHbMilJK3OvL0P6iLyDBRpaGQ3Sb8YDKJBmSQvxGlqdxzTeAw4QMLJCogPkuT4vGsg6b6RomrX1UhtM6T03ia1qR8WMvrpRhwJPQCbG0vTEmaKMJiJ4YKmnGPPLJ7zClZ_OxYoDr-DXk10A-jHAJ-8xX-l88dD-cgYlyOvT6GZxjjvx9Qmzr3WJsFSA2U2gC5sHqrHzD-vUky9I7WFHieOpUW3_hM_-ypZDfWJnn7ehNi8te-EbUUSlhYmn_GoygalbCdx0zvVpZlzZsCEYjvOlU9ZdKFST2BPbjpRKppLhLUnlWHH7-KpP3elyiJy2GJcY1N0JY4LP3ZTJyCI_CVTeNDDbZHUdMD3v-oO78wu4DAK_XgVX_-rCOrt1pFZ_k-FONSVq8zQtts6LVeWcaX60Q-zc4jGvZ7bn88UuNNtiBuq3jzskSgI0jS185-EZd5gBM_ahkcEHnkEVk4DLC6fnKp5V3Cek8xEw7p_ADsVx-cNPR46T3JIblOQil_u4I8gh-w1S9R7J_5QVFDsFsdRWy-yzI2fmzbw7DUsysNUqXPXyFKnUOUFjTAIhiYtLKsXx2YO8l5Dj2P9lLgEkwGq3oxlf7vVG29A1iVtcKtyLqah5hMvi7Dp445jvHzHQmvb7Psi0Yy8_PjepEP0pWZ982NBn75Fx9D04FqBIoHvsAg0hVhykOMoBEdCA8GHzMP8zUDXeH7Gj6QeTYmRL0Q7JLdPxQUGsPyiwPCo9Q-5SirIJpDZjDwtH6_vZ_BrB_kWQSSWdDvd2okqpqaynVhlSutJdyU.pO_I4zL-ky1p1OQPd1Ta2bAV3kpcdOjrvY1whQ7-7Q6kuA-iaVkIoHilDhCslp6_PZ_wdTun96yG8JxQfH56AA';

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

        $jws = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_2));

        $this->assertTrue(!is_null($jws));

        $server_key  = RSAJWKFactory::build
        (
            new RSAJWKPEMPublicKeySpecification
            (
                TestKeys::$public_key_pem,
                JSONWebSignatureAndEncryptionAlgorithms::RS384
            )
        );

        $server_key->setId('rsa_server');
        // and verify signature.
        $res = $jws->setKey($server_key)->verify(JSONWebSignatureAndEncryptionAlgorithms::RS384);

        $this->assertTrue($res);
    }
}