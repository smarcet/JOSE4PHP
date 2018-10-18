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
use \jwt\impl\JWTClaimSet;
use \jwt\JWTClaim;
use \utils\json_types\StringOrURI;
use \utils\json_types\JsonValue;
use \utils\json_types\NumericDate;
use \utils\Base64UrlRepresentation;
use \jwt\impl\UnsecuredJWT;
use \jwt\utils\JWTClaimSetFactory;
use \jwt\RegisteredJWTClaimNames;
use utils\factories\BasicJWTFactory;
use jwe\IJWE;
/**
 * Class JsonWebTokenTest
 */
final class JsonWebTokenTest extends PHPUnit_Framework_TestCase {

    static $epoch ;

    public static function setUpBeforeClass()
    {
        self::$epoch = time();
    }

    /**
     * @return JWTClaimSet
     */
    public function testBuildClaimSet(){

        $epoch_now = self::$epoch;

        $claim_set = new JWTClaimSet(
            new StringOrURI('issuer_test'),
            new StringOrURI('subject_test'),
            new StringOrURI('audience_test'),
            new NumericDate($epoch_now),
            new NumericDate($epoch_now + 3600),
            new JsonValue('jid')
        );

        $this->assertTrue($claim_set->getAudience()->isString() && $claim_set->getAudience()->getString() ===  'audience_test');
        $this->assertTrue($claim_set->getSubject()->isString() && $claim_set->getSubject()->getString()   ===  'subject_test');
        $this->assertTrue($claim_set->getJWTID()->getValue() ===  'jid');

        $issued_date_time    = $claim_set->getIssuedAt()->getDateTime();
        $epoch_now_date_time = new \DateTime("@$epoch_now");

        $this->assertTrue($epoch_now_date_time ==  $issued_date_time);

        return $claim_set;
    }

    /**
     * @depends testBuildClaimSet
     * @param JWTClaimSet $claimSet
     * @throws \utils\exceptions\JsonParseException
     */
    public function testClaimSetToJson(JWTClaimSet $claimSet){

        $epoch_now = self::$epoch;
        $lifetime = $epoch_now +3600;
        $res      = $claimSet->toJson();
        $should   = '{"iss":"issuer_test","sub":"subject_test","aud":"audience_test","iat":'.$epoch_now.',"exp":'.$lifetime.',"jti":"jid"}';

        $this->assertTrue( $res == $should);
    }


    public function testClaimSetToBase64(){

        $lifetime              = 1300819380;
        $base64_representation = new Base64UrlRepresentation();

        $claim_set = new JWTClaimSet(
            new StringOrURI('joe'),
            null,
            null,
            null,
            new NumericDate($lifetime)
        );
        $claim_set->addClaim(new JWTClaim("http://example.com/is_root", new JsonValue(true)));

        $json    = $claim_set->toJson();
        $res     = $base64_representation->encode($json);
        $should  = "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        $this->assertTrue( $res == $should);

        $decoded = $base64_representation->decode($res);

        $should = '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}';

        $this->assertTrue( $decoded == $should);
    }

    public function testUnsecuredJWT(){

        $claim_set = JWTClaimSetFactory::build(array(
            RegisteredJWTClaimNames::Issuer         => 'joe',
            RegisteredJWTClaimNames::ExpirationTime => 1300819380,
            "http://example.com/is_root"            => true,
            'groups'                                => array('admin', 'sudo', 'devs')
        ));

        $unsecured_jwt = UnsecuredJWT::fromClaimSet($claim_set);
        $res           = $unsecured_jwt->toCompactSerialization();
        $should        = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJzdWRvIiwiZGV2cyJdfQ.';

        $this->assertTrue( $res == $should);
    }


    public function testBasiFactory()
    {
        $jwe = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJraWQiOiJwdWJsaWNfa2V5XzEiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.GXnU3QJejpG-AZkps3CDaiwCqCNAfHtiDNPrA7MLp-yQhoRvozpvMbUujQKP-7YzgPQuSMomJwhYIo6J1lyJS7me_8h0ARKoBmZ9sKDAHJrTRY0lRjZmdyKKMZScIrYbXjuKTLmCr3VYTlDatF77rf0C4FXWcWyB6d1SsrT6hOpPWkynVh7L1sGqCaYQRFPq3Q60Ryo-02L5KvB5WVTsHKN2NcqF6sOwO3uLXI_6mPlCMMqMGk5Q8Cu7BnVA4IuK2NB-X9xd1xI7iaa6SS6TYou3ZludfexMFLSzWNxi0w0G9bpUso-b0TxzXmCRVEOhmkfzypqhdWfqKtSz1Jx7Cw.K4nz2gCrqbq6f0pc-WsVLbsv9xK_KXmk1iEzQkHSfsVcckrv8KupmqCb9XINZ1X0NfshNuUIYJ9c_YRVFmsfTA.Ip_XrCxV2-oS5Srx1XwcO0YeT6rFveTkzACmV92K27ihDnkio_vxWwss_tZEPGdhLERNeXSrHoeSiGbEYR1GHvMcLJ32dqOIrkFBdI5kCqO2I0LPPzBX61YuEAf8JDbp9dsjdKmhUymfpFzTrSM-C-E8MtNyfgTvtRAELWr_H6ErJHatkPrRAhh1bzM0BVo_HSViB2VsVdG_PgyA3BLF_BUvCYMwxLpi8Jxlv1SefUsyTAPvDQVE9Sol0i-31662DGZoi3I6VDD3Fox8_8vjabARxjV4LUZ8N4Jt4IzY6IucsDON9MzPNaDk1WkncknqLwDQp0EvwlzCG_WQUsw2HPGn3Y_U-Ju--wOXQQMS0yzZP7GckEP_OpgRhVLLNmV8n300ct4goqg2AmTqpbVbKImje1ldfbqYgFDrMWb6VqKRXXINNYCa5EFBRixZSeur0LIgdoovem4sdwyNrzw6pBxQzMQNt6Jlsf9IExhyuKFXkgIB7NmqbO9SDxYn5q2zE11NBBLZ98F2ylU98N_oovITvz4S6FD9hQ-GqmgQNHx_bl3mBrvTR8NwGsGsyoInhxOx8IA-Mt2az0iVU1KNCGTSwn9jlhqN95-spFjSGw0.Z-jvQzFXXi2liOXetvvXKhSaVnsuLFGZvdE6S9V2kbs';

        $jwt = BasicJWTFactory::build($jwe);

        $this->assertTrue(!is_null($jwt));
        $this->assertTrue($jwt instanceof IJWE);
    }

}