<?php

namespace B2pweb\Jwt\Tests;

use B2pweb\Jwt\EncodingOptions;
use B2pweb\Jwt\JWA;
use B2pweb\Jwt\JwtEncoder;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

class EncodingOptionsTest extends TestCase
{
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
        $this->publicKey = __DIR__.'/assets/public.key';
        $this->privateKey = __DIR__.'/assets/private.key';
    }

    public function test_getter_setter()
    {
        $options = new EncodingOptions($jwks = new JWKSet([
            JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256']),
        ]));

        $this->assertSame('RS256', $options->algorithm());
        $this->assertNull($options->kid());
        $this->assertSame(['alg' => 'RS256'], $options->headers());
        $this->assertSame($jwks, $options->keySet());

        $options
            ->setAlgorithm('RS512')
            ->setKid('foo')
            ->setHeaders(['foo' => 'bar'])
        ;

        $this->assertSame('RS512', $options->algorithm());
        $this->assertSame('foo', $options->kid());
        $this->assertSame(['foo' => 'bar', 'alg' => 'RS512', 'kid' => 'foo'], $options->headers());

        $options->setHeader('a', 'b');
        $this->assertSame(['foo' => 'bar', 'a' => 'b', 'alg' => 'RS512', 'kid' => 'foo'], $options->headers());
    }

    public function test_selectSignatureKey()
    {
        $options = new EncodingOptions(new JWKSet([
            $k1 = JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'k1']),
            $k2 = JWKFactory::createFromKeyFile(__DIR__.'/assets/other.key', null, ['use' => 'sig', 'alg' => 'RS256', 'kid' => 'k2']),
            $k3 = JWKFactory::createFromSecret('azertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiopazertyuiop', ['alg' => 'HS256', 'kid' => 'k3']),
            $k4 = JWKFactory::createFromKeyFile(__DIR__.'/assets/other.key', null, ['use' => 'enc', 'alg' => 'RS256', 'kid' => 'k4']),
        ]));

        $this->assertSame($k1, $options->selectSignatureKey(new JWA()));
        $this->assertSame($k3, $options->setAlgorithm('HS256')->selectSignatureKey(new JWA()));
        $this->assertSame($k2, $options->setAlgorithm('RS256')->setKid('k2')->selectSignatureKey(new JWA()));

        try {
            $options->setAlgorithm('RS256')->setKid('k4')->selectSignatureKey(new JWA());
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Cannot found any valid key', $e->getMessage());
        }

        try {
            $options->setAlgorithm('invalid')->setKid(null)->selectSignatureKey(new JWA());
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('The algorithm "invalid" is not supported.', $e->getMessage());
        }

        try {
            $options->setAlgorithm('RS256')->setKid('invalid')->selectSignatureKey(new JWA());
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Cannot found any valid key', $e->getMessage());
        }

        try {
            $options->setAlgorithm('RS512')->setKid(null)->selectSignatureKey(new JWA());
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Cannot found any valid key', $e->getMessage());
        }
    }

    public function test_fromKey()
    {
        $options = EncodingOptions::fromKey($key = JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig']));
        $this->assertSame('RS256', $options->algorithm());
        $this->assertSame($key, $options->selectSignatureKey(new JWA()));
        $this->assertNull($options->kid());
        $this->assertSame(['alg' => 'RS256'], $options->headers());

        $options = EncodingOptions::fromKey($key = JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS512']));
        $this->assertSame('RS512', $options->algorithm());
        $this->assertSame($key, $options->selectSignatureKey(new JWA()));
        $this->assertNull($options->kid());
        $this->assertSame(['alg' => 'RS512'], $options->headers());

        $options = EncodingOptions::fromKey($key = JWKFactory::createFromKeyFile($this->privateKey, null, ['use' => 'sig', 'alg' => 'RS512', 'kid' => 'foo']));
        $this->assertSame('RS512', $options->algorithm());
        $this->assertSame($key, $options->selectSignatureKey(new JWA()));
        $this->assertSame('foo', $options->kid());
        $this->assertSame(['alg' => 'RS512', 'kid' => 'foo'], $options->headers());
    }
}
