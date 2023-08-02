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
        $decoder = clone $this;

        $decoder->jwa = $decoder->jwa->filter($algorithms);

        return $decoder;
    }

    /**
     * Decode the JWT string
     *
     * @param mixed|ClaimsInterface $payload Payload to encode. If ClaimsInterface is used, {@see ClaimsInterface::toJson()} will be used to encode the payload.
     * @param JWKSet $keySet Keys to use
     * @param string $algorithm Algorithm to use
     * @param string|null $kid Key ID to use. If null, the first key matching the algorithm will be used
     *
     * @return string The encoded JWT
     *
     * @throws InvalidArgumentException When cannot found any valid key, or the requested algorithm is not supported
     * @psalm-suppress NullArgument
     * @psalm-suppress TooManyArguments
     */
    public function encode($payload, JWKSet $keySet, string $algorithm = 'RS256', ?string $kid = null): string
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

        $key = $keySet->selectKey(
            'sig',
            $manager->get($algorithm),
            $kid ? ['kid' => $kid] : []
        );

        if (!$key) {
            throw new InvalidArgumentException('Cannot found any valid key');
        }

        $sigHeader = ['alg' => $algorithm];

        if ($kid) {
            $sigHeader['kid'] = $kid;
        }

        $payload = $payload instanceof ClaimsInterface ? $payload->toJson() : json_encode($payload);

        $jws = $jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($key, $sigHeader)
            ->build()
        ;

        return $this->serializer->serialize($jws);
    }
}
