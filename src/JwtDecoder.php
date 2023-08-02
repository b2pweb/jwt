<?php

namespace B2pweb\Jwt;

use Exception;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

use function is_array;

/**
 * Decode utility for JWT
 *
 * @todo handle JWE
 */
final class JwtDecoder
{
    /**
     * @var JWA
     */
    private $jwa;

    /**
     * @var JWSSerializerManager
     */
    private $serializerManager;

    /**
     * JwtParser constructor.
     *
     * @param JWA|null $jwa
     * @param JWSSerializerManager|null $serializerManager
     */
    public function __construct(?JWA $jwa = null, ?JWSSerializerManager $serializerManager = null)
    {
        $this->jwa = $jwa ?: new JWA();
        $this->serializerManager = $serializerManager ?: new JWSSerializerManager([new CompactSerializer()]);
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
     * @return self A new JwtDecoder instance, with filtered algorithms
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
     * @param string $jwt String to decode
     * @param JWKSet $keySet Keys to use
     *
     * @return JWT
     *
     * @throws InvalidArgumentException When cannot decode the JWT string
     */
    public function decode(string $jwt, JWKSet $keySet): JWT
    {
        $loader = new JWSLoader(
            $this->serializerManager,
            new JWSVerifier($this->jwa->manager()),
            new HeaderCheckerManager([new AlgorithmChecker($this->jwa->manager()->list())], [new JWSTokenSupport()])
        );

        try {
            $decoded = $loader->loadAndVerifyWithKeySet($jwt, $keySet, $signatureOffset);
        } catch (Exception $e) {
            throw new InvalidArgumentException('Invalid JWT or signature', 0, $e);
        }

        /** @psalm-suppress PossiblyNullArrayOffset */
        $signature = $decoded->getSignatures()[$signatureOffset];

        $payload = json_decode((string) $decoded->getPayload(), true);

        if (!is_array($payload)) {
            throw new InvalidArgumentException('Invalid JWT payload');
        }

        return new JWT(
            $jwt,
            $signature->getProtectedHeader() + $signature->getHeader(),
            $payload
        );
    }
}
