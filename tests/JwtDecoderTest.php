<?php

namespace Parroauth2\Client\Jwt;

use B2pweb\Jwt\JWT;
use B2pweb\Jwt\JwtDecoder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

/**
 * Class JwtDecoderTest
 */
class JwtDecoderTest extends TestCase
{
    /**
     * @var JwtDecoder
     */
    private $decoder;

    /**
     * @var CompactSerializer
     */
    private $serializer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->decoder = new JwtDecoder();
        $this->serializer = new CompactSerializer();
    }

    /**
     *
     */
    public function test_decode_success()
    {
        $jws = $this->jwsBuilder([new RS256()])
            ->create()
            ->addSignature(JWKFactory::createFromKeyFile(__DIR__.'/assets/private.key'), ['alg' => 'RS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $decoded = $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/assets/public.key', null, ['alg' => 'RS256'])
        ]));

        $this->assertEquals($jws, $decoded->encoded());
        $this->assertEquals(['foo' => 'bar'], $decoded->payload());
        $this->assertEquals(['alg' => 'RS256'], $decoded->headers());
    }

    /**
     *
     */
    public function test_decode_success_with_symmetric_signature()
    {
        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('my-keymy-keymy-keymy-keymy-keymy-keymy-keymy-key'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $decoded = $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromSecret('my-keymy-keymy-keymy-keymy-keymy-keymy-keymy-key')
        ]));

        $this->assertEquals($jws, $decoded->encoded());
        $this->assertEquals(['foo' => 'bar'], $decoded->payload());
        $this->assertEquals(['alg' => 'HS256'], $decoded->headers());
    }

    /**
     *
     */
    public function test_decode_key_type_do_not_match()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret(file_get_contents(__DIR__.'/assets/private.key')), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/assets/public.key', null, ['alg' => 'RS256'])
        ]));
    }

    /**
     *
     */
    public function test_decode_invalid_key()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $jws = $this->jwsBuilder([new RS256()])
            ->create()
            ->addSignature(JWKFactory::createFromKeyFile(__DIR__.'/assets/private.key'), ['alg' => 'RS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/assets/public-other.key', null, ['alg' => 'RS256'])
        ]));
    }

    /**
     *
     */
    public function test_decode_invalid_key_with_symmetric()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecret'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromSecret('invalid', ['alg' => 'HS256'])
        ]));
    }

    /**
     *
     */
    public function test_decode_not_a_jwt()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $this->decoder->decode('invalid', new JWKSet([
            JWKFactory::createFromSecret('invalid', ['alg' => 'HS256'])
        ]));
    }

    /**
     *
     */
    public function test_supportedAlgorithms()
    {
        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecret'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;
        $jws = $this->serializer->serialize($jws);

        $jwks = new JWKSet([JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecret', ['alg' => 'HS256'])]);

        $this->assertNotSame($this->decoder, $this->decoder->supportedAlgorithms(['HS256']));
        $this->assertEquals(['HS256'], $this->decoder->supportedAlgorithms(['HS256'])->jwa()->manager()->list());

        $this->assertInstanceOf(JWT::class, $this->decoder->supportedAlgorithms(['HS256'])->decode($jws, $jwks));

        try {
            $this->decoder->supportedAlgorithms(['RS256'])->decode($jws, $jwks);
            $this->fail('Expects InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {}
    }

    /**
     *
     */
    public function test_decode_payload_not_object()
    {
        $this->expectExceptionMessage('Invalid JWT payload');
        $jws = $this->jwsBuilder([new RS256()])
            ->create()
            ->addSignature(JWKFactory::createFromKeyFile(__DIR__.'/assets/private.key'), ['alg' => 'RS256'])
            ->withPayload('"foo"')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $decoded = $this->decoder->decode($jws, new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/assets/public.key', null, ['alg' => 'RS256'])
        ]));
    }

    private function jwsBuilder(array $algo): JWSBuilder
    {
        $ctor = (new \ReflectionClass(JWSBuilder::class))->getConstructor();

        return $ctor->getNumberOfParameters() === 1
            ? new JWSBuilder(new AlgorithmManager($algo))
            : new JWSBuilder(null, new AlgorithmManager($algo))
        ;
    }
}
