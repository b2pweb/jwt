<?php

namespace B2pweb\Jwt;

use Base64Url\Base64Url;
use InvalidArgumentException;

use function count;
use function explode;
use function is_array;
use function json_decode;

/**
 * Store the parsed JWT data
 */
final class JWT extends Claims
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
     * JWT constructor.
     *
     * @param string $encoded
     * @param array $headers
     * @param array<string, mixed> $payload
     */
    public function __construct(string $encoded, array $headers, array $payload)
    {
        parent::__construct($payload);

        $this->encoded = $encoded;
        $this->headers = $headers;
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
        return $this->toArray();
    }

    /**
     * Raw decode a JWT token, without any validation
     * This method is unsafe, on should be used only if key cannot be resolved yet
     *
     * @param string $jwt The JWT string
     *
     * @return JWT The decoded JWT
     *
     * @see JwtDecoder::decode() For a safe decoding
     */
    public static function fromJwtUnsafe(string $jwt): JWT
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid JWT');
        }

        $headers = json_decode(Base64Url::decode($parts[0]), true);
        $payload = json_decode(Base64Url::decode($parts[1]), true);

        if (!is_array($headers) || !is_array($payload)) {
            throw new InvalidArgumentException('Invalid JWT');
        }

        return new JWT($jwt, $headers, $payload);
    }
}
