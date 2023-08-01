<?php

namespace B2pweb\Jwt;

/**
 * Store the parsed JWT data
 */
final class JWT
{
    /**
     * Raw encoded payload of the JWT
     *
     * @var string
     */
    private $encoded;

    /**
     * Merged value of protected and unprotected headers
     *
     * @var array
     */
    private $headers;

    /**
     * The payload
     * Should be array|string for handle wrapped JWT (i.e. JWS into a JWE)
     *
     * @var array
     */
    private $payload;

    /**
     * JWT constructor.
     *
     * @param string $encoded
     * @param array $headers
     * @param array $payload
     */
    public function __construct(string $encoded, array $headers, array $payload)
    {
        $this->encoded = $encoded;
        $this->headers = $headers;
        $this->payload = $payload;
    }

    /**
     * Get the raw encoded value of the JWT
     *
     * @return string
     */
    public function encoded(): string
    {
        return $this->encoded;
    }

    /**
     * Merged value of protected and unprotected headers
     *
     * @return array
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * The JWT payload
     *
     * @return array
     */
    public function payload(): array
    {
        return $this->payload;
    }
}
