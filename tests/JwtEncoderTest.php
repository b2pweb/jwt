<?php

namespace B2pweb\Jwt\Tests;

use B2pweb\Jwt\Claims;
use B2pweb\Jwt\EncodingOptions;
use B2pweb\Jwt\JWA;
use B2pweb\Jwt\JwtDecoder;
use B2pweb\Jwt\JwtEncoder;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

class JwtEncoderTest extends TestCase
{
    /**
     * @var JwtEncoder
     */
    private $encoder;
    /**
     * @var string
     */
    private $publicKey;
    /**
     * @var string
     */
    private $privateKey;

    protected function setUp(): void
    {
        $this->encoder = new JwtEncoder();
        $this->publicKey = __DIR__.'/assets/public.key';
        $this->privateKey = __DIR__.'/assets/private.key';
    }

    public function test_encode_simple()
    {
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            new JWKSet([
                JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']),
            ])
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256']),
        ]));

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256'], $jwt->headers());
    }

    public function test_encode_simple_with_encoding_options()
    {
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            EncodingOptions::fromKey(JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']))
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256']),
        ]));

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256'], $jwt->headers());
    }

    public function test_encode_with_claims_object()
    {
        $token = $this->encoder->encode(
            new Claims(['foo' => 'http://foo.bar']),
            new JWKSet([
                JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']),
            ])
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256']),
        ]));

        $this->assertSame(['foo' => 'http://foo.bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256'], $jwt->headers());
    }

    public function test_encode_with_claims_object_with_encoding_options()
    {
        $token = $this->encoder->encode(
            new Claims(['foo' => 'http://foo.bar']),
            EncodingOptions::fromKey(JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']))
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256']),
        ]));

        $this->assertSame(['foo' => 'http://foo.bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256'], $jwt->headers());
    }

    public function test_encode_symmetric_algo()
    {
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            $jwks = new JWKSet([
                JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecretsecretsecret', ['alg' => 'HS256']),
            ]),
            'HS256'
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, $jwks);

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'HS256'], $jwt->headers());
    }

    public function test_encode_with_encoding_options()
    {
        $jwks = new JWKSet([
            JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecretsecretsecret', ['alg' => 'HS256']),
        ]);
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            (new EncodingOptions($jwks))
                ->setAlgorithm('HS256')
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, $jwks);

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'HS256'], $jwt->headers());
    }

    public function test_encode_with_kid()
    {
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            new JWKSet([
                JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'foo']),
                JWKFactory::createFromKeyFile(__DIR__ . '/assets/other.key', null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'bar'])
            ]),
            'RS256',
            'bar'
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__ . '/assets/public-other.key', null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'bar'])
        ]));

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256', 'kid' => 'bar'], $jwt->headers());
    }

    public function test_encode_with_kid_with_encoding_options()
    {
        $token = $this->encoder->encode(
            ['foo' => 'bar'],
            (new EncodingOptions(
                new JWKSet([
                    JWKFactory::createFromKeyFile($this->publicKey, null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'foo']),
                    JWKFactory::createFromKeyFile(__DIR__ . '/assets/other.key', null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'bar'])
                ])
            ))
                ->setKid('bar')
        );

        $decoder = new JwtDecoder();
        $jwt = $decoder->decode($token, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__ . '/assets/public-other.key', null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'bar'])
        ]));

        $this->assertSame(['foo' => 'bar'], $jwt->payload());
        $this->assertSame(['alg' => 'RS256', 'kid' => 'bar'], $jwt->headers());
    }

    public function test_encode_invalid_algo()
    {
        $this->expectExceptionMessage('The algorithm "invalid" is not supported.');

        $this->encoder->encode(
            ['foo' => 'bar'],
            new JWKSet([
                JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']),
            ]),
            'invalid'
        );
    }

    public function test_encode_key_do_not_match()
    {
        $this->expectExceptionMessage('Cannot found any valid key');

        $this->encoder->encode(
            ['foo' => 'bar'],
            EncodingOptions::fromKey(JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS512']))
                ->setAlgorithm('RS256')
        );
    }

    public function test_limit_supportedAlgorithms()
    {
        $jwks = new JWKSet([
            JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']),
            JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecretsecretsecret', ['alg' => 'HS256']),
        ]);

        $this->assertEquals(['RS256', 'RS384', 'RS512'], $this->encoder->jwa()->algorithmsByType(JWA::TYPE_RSA));

        $options = new EncodingOptions($jwks);

        $this->assertNotEmpty($this->encoder->encode(['foo' => 'bar'], $options->setAlgorithm('RS256')));
        $this->assertNotEmpty($this->encoder->encode(['foo' => 'bar'], $options->setAlgorithm('HS256')));

        $encoder = $this->encoder->supportedAlgorithms(['RS256']);
        $this->assertNotEquals($this->encoder, $encoder);

        $this->assertEquals(['RS256'], $encoder->jwa()->algorithmsByType(JWA::TYPE_RSA));
        $this->assertNotEmpty($encoder->encode(['foo' => 'bar'], $options->setAlgorithm('RS256')));

        try {
            $encoder->encode(['foo' => 'bar'], $options->setAlgorithm('HS256'));
            $this->fail('Should throw an exception');
        } catch (\Exception $e) {
            $this->assertSame('The algorithm "HS256" is not supported.', $e->getMessage());
        }
    }
}
