<?php namespace utils\services;
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
use utils\services\impl\RandomNumberGeneratorService;
/**
 * Class Utils_Registry
 * @package utils\services
 */
final class Utils_Registry {
    
    const RandomNumberGeneratorService = 'RandomNumberGeneratorService';

    /**
     * @var Utils_Registry
     */
    private static $instance;

    private $services = array();

    private function __construct(){

        $this->services[self::RandomNumberGeneratorService] = new RandomNumberGeneratorService;
    }

    private function __clone(){}

    /**
     * @return Utils_Registry
     */
    public static function getInstance(){
        if(!is_object(self::$instance)){
            self::$instance = new Utils_Registry();
        }
        return self::$instance;
    }

    /**
     * @param string $service_name
     * @return null|IService
     */
    public function get($service_name){
        if(!array_key_exists($service_name,  $this->services))
            throw new \InvalidArgumentException('unknown service!');

        return $this->services[$service_name];
    }

    /**
     * @param string $service_name
     * @param IService $service
     * @return $this
     */
    public function add($service_name, IService $service){
        $this->services[$service_name] = $service;
        return $this;
    }
}