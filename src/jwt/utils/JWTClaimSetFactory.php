<?php namespace jwt\utils;
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
use jwt\IJWTClaimSet;
use jwt\JWTClaim;
use jwt\RegisteredJWTClaimNames;
use utils\json_types\JsonValue;
use \ReflectionClass;
/**
 * Class JWTClaimSetFactory
 * @package jwt\utils
 */
class JWTClaimSetFactory {

    const ClaimSetTypeImplementation = 'jwt\impl\JWTClaimSet';

    /**
     * @param array $raw_claims
     * @return IJWTClaimSet
     */
    public static function build(array $raw_claims){

        $args = array();

        foreach(RegisteredJWTClaimNames::$registered_claim_set as $claim_name){
            $value = isset($raw_claims[$claim_name]) ? $raw_claims[$claim_name] : null;
            $type  = RegisteredJWTClaimNames::$registered_claim_set_types[$claim_name];
            if(!is_null($value))
            {
                $class    = new ReflectionClass($type);
                $value    = $class->newInstanceArgs(array($value));
            }
            array_push($args, $value);
            unset($raw_claims[$claim_name]);
        }


        $class     = new ReflectionClass(self::ClaimSetTypeImplementation);
        $claim_set = $class->newInstanceArgs($args);

        // unregistered claims

        foreach($raw_claims as $k => $v){
            $claim_set->addClaim(new JWTClaim($k, new JsonValue($v)));
        }

        return $claim_set;
    }
}