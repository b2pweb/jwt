# JWT
[![build](https://github.com/b2pweb/jwt/actions/workflows/php.yml/badge.svg)](https://github.com/b2pweb/jwt/actions/workflows/php.yml)
[![Packagist Version](https://img.shields.io/packagist/v/b2pweb/jwt.svg)](https://packagist.org/packages/b2pweb/jwt)
[![Total Downloads](https://img.shields.io/packagist/dt/b2pweb/jwt.svg)](https://packagist.org/packages/b2pweb/jwt)
[![Type Coverage](https://shepherd.dev/github/b2pweb/jwt/coverage.svg)](https://shepherd.dev/github/b2pweb/jwt)

Library for parse and create JWT (JSON Web Token) in PHP, using [PHP JWT Framework](https://github.com/web-token/jwt-framework).

## Installation

Install with composer :

```bash
composer require b2pweb/jwt
```

## Simple usage

```php
<?php

// Define algorithms
$jwa = new \B2pweb\Jwt\JWA();
$jwa = $jwa->filter(['HS256', 'HS512', 'RS256', 'RS512']); // Filter enabled algorithms

// Define your keys
$jwks = new \Jose\Component\Core\JWKSet([
    \Jose\Component\KeyManagement\JWKFactory::createFromKeyFile($privKey, null, ['use' => 'sig', 'kid' => 'key-user']),
    // ...
]);

// Encode a payload to JWT
$encoder = new \B2pweb\Jwt\JwtEncoder($jwa);
$jwt = $encoder->encode(
    [
        'iss' => 'https://example.com',
        'aud' => 'https://example.com',
        'iat' => time(),
        'exp' => time() + 3600,
        'sub' => '1234567890',
        'name' => 'John Doe',
        'admin' => true,
    ],
    // You can configure encoding options here, like the key to use, the algorithm, ...
    (new \B2pweb\Jwt\EncodingOptions($jwks))
        ->setAlgorithm('RS512')
        ->setKid('key-user')
);

// You can also use an object that implements \B2pweb\Jwt\ClaimsInterface
// allowing you to customize the claims serialization to JSON
// If you extends \B2pweb\Jwt\Claims, you can define Claims::$encodingFlags on the subclass to customize the JSON encoding flags
$claims = new \B2pweb\Jwt\Claims([
    'iss' => 'https://example.com',
    'aud' => 'https://example.com',
    'iat' => time(),
    'exp' => time() + 3600,
    'sub' => '1234567890',
    'name' => 'John Doe',
    'admin' => true,
]);
$jwt = $encoder->encode(
    $claims,
    // You can use EncodingOptions::fromKey, which will automatically set the algorithm and the kid from the given key
    \B2pweb\Jwt\EncodingOptions::fromKey(\Jose\Component\KeyManagement\JWKFactory::createFromSecret($secret, ['use' => 'sig', 'alg' => 'HS256']))
);

// Decode a JWT
$decoder = new \B2pweb\Jwt\JwtDecoder($jwa);

$token = $decoder->decode($jwt, $jwks); // Return a \B2pweb\Jwt\Claims object
$token->claim('iss'); // Return 'https://example.com'

// Yan can also define allowed algorithms using JwtDecoder::supportedAlgorithms()
$token = $decoder->supportedAlgorithms(['RS256', 'RS512'])->decode($jwt, $jwks);

// You can also decode a JWT without verifying the signature
$token = \B2pweb\Jwt\JWT::fromJwtUnsafe($jwt);
```
