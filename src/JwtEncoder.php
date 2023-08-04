<?php

namespace B2pweb\Jwt;

use InvalidArgumentException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;

use function json_encode;

/**
 * Encode utility for JWT
 *
 * @todo handle JWE
 */
final class JwtEncoder
{
    /**
     * @var JWA
     */
    private $jwa;

    /**
     * @var JWSSerializer
     */
    private $serializer;

    /**
     * JwtParser constructor.
     *
     * @param JWA|null $jwa
     * @param JWSSerializer|null $serializer
     */
    public function __construct(?JWA $jwa = null, ?JWSSerializer $serializer = null)
    {
        $this->jwa = $jwa ?? new JWA();
        $this->serializer = $serializer ?? new CompactSerializer();
    }

    /**
     * Get the supported algorithms
     *
     * @return JWA
     */
    public function jwa(): JWA
    {
        return $this->jwa;
    }

    /**
     * Define supported algorithms
     *
     * @param string[] $algorithms
     *
     * @return self A new JwtEncoder instance, with filtered algorithms
     *
     * @see JWA::filter()
     */
    public function supportedAlgorithms(array $algorithms): self
    {
        $encoder = clone $this;

        $encoder->jwa = $encoder->jwa->filter($algorithms);

        return $encoder;
    }

    /**
     * Decode the JWT string
     *
     * @param mixed|ClaimsInterface $payload Payload to encode. If ClaimsInterface is used,
     *                                       {@see ClaimsInterface::toJson()} will be used to encode the payload.
     * @param JWKSet|EncodingOptions $options Options to use for encoding.
     *                                        Can be a JWKSet for use legacy method signature.
     * @param string $algorithm Algorithm to use.
     *                          Deprecated: use EncodingOptions instead.
     * @param string|null $kid Key ID to use. If null, the first key matching the algorithm will be used.
     *                         Deprecated: use EncodingOptions instead.
     *
     * @return string The encoded JWT
     *
     * @throws InvalidArgumentException When cannot found any valid key, or the requested algorithm is not supported
     * @psalm-suppress NullArgument
     * @psalm-suppress TooManyArguments
     */
    public function encode($payload, $options, string $algorithm = 'RS256', ?string $kid = null): string
    {
        static $isLegacyJwsBuilder = null;

        if ($isLegacyJwsBuilder === null) {
            $ctor = (new \ReflectionClass(JWSBuilder::class))->getConstructor();
            /** @psalm-suppress PossiblyNullReference */
            $isLegacyJwsBuilder = $ctor->getNumberOfParameters() === 2;
        }

        $manager = $this->jwa->manager();
        $jwsBuilder = $isLegacyJwsBuilder
            ? new JWSBuilder(null, $manager)
            : new JWSBuilder($manager)
        ;

        if ($options instanceof JWKSet) {
            $options = new EncodingOptions($options, $algorithm, $kid);
        }

        $key = $options->selectSignatureKey($this->jwa);

        $payload = $payload instanceof ClaimsInterface ? $payload->toJson() : json_encode($payload);

        $jws = $jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($key, $options->headers())
            ->build()
        ;

        return $this->serializer->serialize($jws);
    }
}
