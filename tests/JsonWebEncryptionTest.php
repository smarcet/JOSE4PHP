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

use jws\JWSFactory;
use jws\impl\specs\JWS_ParamsSpecification;
use jws\impl\specs\JWS_CompactFormatSpecification;

use jwe\impl\JWEFactory;
use jwe\impl\specs\JWE_CompactFormatSpecification;
use jwe\impl\specs\JWE_ParamsSpecification;

use utils\json_types\StringOrURI;
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

        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $alg     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::RSA1_5);
        $enc     = new  StringOrURI(JSONWebSignatureAndEncryptionAlgorithms::A256CBC_HS512);
        $jwe     = JWEFactory::build( new JWE_ParamsSpecification($recipient_key, $alg, $enc, $payload ));

        $compact_serialization = $jwe->toCompactSerialization();

        $this->assertTrue(!empty($compact_serialization));
    }

    public function testDecrypt(){

        $payload_jws      = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InJzYV9zZXJ2ZXIifQ.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJzdWRvIiwiZGV2cyJdfQ.Zp_rHs2EqCiXuAg_c-kQ0LuRtXwqLADxOOT-0AXYf21u9cYD4rTfpjGprQC4cpT9TbHPrpJpXUVapar1GFolwW9gcKW530Lf00r6qOL0eZ5UvuR_7uPKe4mVlxz5IMFK9wqWyBjKhA5Jgd-hjYFaHIocafxOZ4ihUwIikdefw7wNrZlAd8nmVvSkpWDvP2H5FiXwQd7PZds9KiZxJD9up3yWc36Rpbsr33edJEUHK61Z45yBIDDhDkj2UVeF-C9NYYIYLctaYmRFxPOi39gBqMuOwGGJuT221Ifl0LS8DHqvIi1FVfVWGeXS5piqcpD8gahu8aJ88emrR1aP-Dsi8w';
        $jwe_compact_form = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.h99UHSZVHRDTQhea4ES7657BbTx-edQbkAaAoqORVjmKILHp7loIcOiwGIDf8Ev43RBKxptrytRxTkAJXofhi9MYEA-MzJRnnr68FXeNsQ9X4A_OtJvxuYTR52D06RqpLCR_15q-EpTjkphPY3c2Mtm4NhcBYdws103zNMwxTWGAwM04MRi9J_F9qM24seuEGsKjFaLTWpny1tBg_vfgvsQ35d0Otp-V3FOoV9VGMgXK3vyP6biVQQhxKsL7iFaTp9gL-LksjE3Lxpnc7cuc1QolrQCYxWLIGVkpP6FOjI1oqiDTpKVIBjtHJKkdbrawHW2p9saSTWS_HAcDQmNrow.Oi27Prc6MxI.Yx0FJYoahBa0L23XFxte4ttS5IL25qbkZZjcfLuiQSlT6PEq7_gI-3hhnyBwE0MvpUIkqRzCJeGSM4rD9LSYYEmeYVoISXVpBKWiB8iCyuIK-Yvbb2oj_ho7KopJ-kZhZR-L2GEMRuHmhPZzr88fixfe1IsDSZd2_JnafDn9v167pMQ1aNyEw2ZUYQMctkxUlOgDI7zqI7t-MfX4dvxkwD_3-fXx7r8ILUbT0wooRQ7Mwh6wrnXBPqTTkaVyaYB58dUqE3lF8sd2sxKpn9WnHoZE_Stsxi_eiWVKeHi9_PljLnAekvzKPegm5I2BOY1lkq9ggiwF5nCv3094FFidlTqxafH8XTiLH6fT0Zb-TcdTcd6PmKK3fW3-NoPMTz_9Iz9W4JyljTvgJwi-fSNaRUlSzWJdWlQ9-eqxd0HO1wSSo7Kpk5h8NOlDwKEWlRuHgIQPoPkFFG6iMxSVCAcDXzAF6a86kkZitac5Hj1nq1y5hFDMeRPz5gjuoBMGMELI8kmK64L6Y_z0FnrVfackqDOXKin2gBVjIr24unrq0c03xgaoPCX88I663-aoTjsc70JJL92Y6FdTyV8MQ5ZE8L9eCLJwrxVQgj8_dOEFYlLBpOY4CabeINl5qZ-y4mscWLoaP9iticF-G7_OmJH9v7-h6AQOnRU-ShHT9y5fzYxDwNOzVhfJUIJivKoS25tIoSRCNw-Nl6PlBkM271n-Dg.nk4MG8hjImJDW6ZZ0gpH0e4_YOnWmdFij6lSIp-HGF0';

        $recipient_key = RSAJWKFactory::build(new RSAJWKPEMPrivateKeySpecification(TestKeys::$private_key2_pem));
        $recipient_key->setKeyUse(JSONWebKeyPublicKeyUseValues::Encryption)->setId('recipient_public_key');

        $jwe_2 = JWEFactory::build( new JWE_CompactFormatSpecification( $jwe_compact_form));

        $this->assertTrue(!is_null($jwe_2));

        $jwe_2->setRecipientKey($recipient_key);

        $payload_2 = $jwe_2->getPlainText();

        $this->assertTrue($payload_2 === $payload_jws);

        $jws = JWSFactory::build( new JWS_CompactFormatSpecification ($payload_jws));

        $this->assertTrue(!is_null($jws));
    }
}