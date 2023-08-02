<?php

namespace B2pweb\Jwt;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * Options for encoding a JWT
 *
 * @see JwtEncoder::encode()
 */
final class EncodingOptions
{
    /**
     * @var JWKSet
     */
    private $keySet;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var string|null
     */
    private $kid;

    /**
     * @var array<string, mixed>
     */
    private $headers = [];

    /**
     * @param JWKSet $keySet
     * @param string $algorithm
     * @param string|null $kid
     * @param array<string, mixed> $headers
     */
    public function __construct(JWKSet $keySet, string $algorithm = 'RS256', ?string $kid = null, array $headers = [])
    {
        $this->keySet = $keySet;
        $this->algorithm = $algorithm;
        $this->kid = $kid;
        $this->headers = $headers;
    }

    /**
     * Get the requested signature algorithm
     *
     * @return string
     */
    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Define the signature algorithm
     *
     * @param string $algorithm
     *
     * @return $this
     */
    public function setAlgorithm(string $algorithm): EncodingOptions
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Get the defined key id
     *
     * @return string|null
     */
    public function kid(): ?string
    {
        return $this->kid;
    }

    /**
     * Define the key id
     *
     * @param string|null $kid
     * @return $this
     */
    public function setKid(?string $kid): EncodingOptions
    {
        $this->kid = $kid;
        return $this;
    }

    /**
     * Define additional headers
     *
     * @param array<string, mixed> $headers
     * @return $this
     */
    public function setHeaders(array $headers): EncodingOptions
    {
        $this->headers = $headers;
        return $this;
    }

    /**
     * Define an additional header
     *
     * @param string $key The header key
     * @param mixed $value The header value
     *
     * @return $this
     */
    public function setHeader(string $key, $value): EncodingOptions
    {
        $this->headers[$key] = $value;
        return $this;
    }

    /**
     * Try to select a signature key
     *
     * @param JWA $algorithms The supported algorithms
     * @return JWK
     *
     * @throws InvalidArgumentException If there is no valid key, or requested algorithm is not supported
     */
    public function selectSignatureKey(JWA $algorithms): JWK
    {
        $key = $this->keySet->selectKey(
            'sig',
            $algorithms->manager()->get($this->algorithm),
            $this->kid ? ['kid' => $this->kid] : []
        );

        if (!$key) {
            throw new InvalidArgumentException('Cannot found any valid key');
        }

        return $key;
    }

    /**
     * Get the signature headers
     *
     * @return array<string, mixed>
     */
    public function headers(): array
    {
        $headers = $this->headers;
        $headers['alg'] = $this->algorithm;

        if ($this->kid) {
            $headers['kid'] = $this->kid;
        }

        return $headers;
    }

    /**
     * Create options from a key
     * Algorithm and kid will be resolved from the key
     *
     * @param JWK $key
     * @return self
     */
    public static function fromKey(JWK $key): self
    {
        $options = new self(new JWKSet([$key]));

        if ($key->has('alg')) {
            $options->setAlgorithm((string) $key->get('alg'));
        }

        if ($key->has('kid')) {
            $options->setKid((string) $key->get('kid'));
        }

        return $options;
    }
}
