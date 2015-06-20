# JOSE4PHP

JSON Web Token (JWT)/JSON Web Signature (JWS)/JSON Web Key (JWK)/JSON Web Encryption (JWE)/JSON Web Algorithms (JWA)
Implementation

    * https://tools.ietf.org/html/rfc7519
    * https://tools.ietf.org/html/rfc7515
    * https://tools.ietf.org/html/rfc7516
    * https://tools.ietf.org/html/rfc7517
    * https://tools.ietf.org/html/rfc7518

[![Build Status](https://travis-ci.org/smarcet/JOSE4PHP.svg)](https://travis-ci.org/smarcet/JOSE4PHP)

## Prerequisites

    * LAMP/LEMP environment
    * PHP >= 5.3.0
    * composer (https://getcomposer.org/)

## Install

run following commands on root folder


    * curl -s https://getcomposer.org/installer | php
    * php composer.phar install --prefer-dist
    * php composer.phar dump-autoload --optimize
    * phpunit --bootstrap vendor/autoload.php 