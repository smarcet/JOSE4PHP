# JOSE4PHP

JSON Web Token (JWT)/JSON Web Signature (JWS)/JSON Web Key (JWK)/JSON Web Encryption (JWE)/JSON Web Algorithms (JWA)
Implementation

    * https://tools.ietf.org/html/rfc7519
    * https://tools.ietf.org/html/rfc7515
    * https://tools.ietf.org/html/rfc7516
    * https://tools.ietf.org/html/rfc7517
    * https://tools.ietf.org/html/rfc7518

[![Build Status](https://travis-ci.org/smarcet/JOSE4PHP.svg)](https://travis-ci.org/smarcet/JOSE4PHP)
[![Latest Stable Version](https://poser.pugx.org/smarcet/jose4php/v/stable)](https://packagist.org/packages/smarcet/jose4php)
[![Total Downloads](https://poser.pugx.org/smarcet/jose4php/downloads)](https://packagist.org/packages/smarcet/jose4php)
[![Latest Unstable Version](https://poser.pugx.org/smarcet/jose4php/v/unstable)](https://packagist.org/packages/smarcet/jose4php)
[![License](https://poser.pugx.org/smarcet/jose4php/license)](https://packagist.org/packages/smarcet/jose4php)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/smarcet/JOSE4PHP/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/smarcet/JOSE4PHP/?branch=master)

## Prerequisites

    * LAMP/LEMP environment
    * PHP >= 7.2
    * composer (https://getcomposer.org/)

## Install

run following commands on root folder


    * curl -s https://getcomposer.org/installer | php
    * php composer.phar install --prefer-dist
    * php composer.phar dump-autoload --optimize
    * phpunit --bootstrap vendor/autoload.php 