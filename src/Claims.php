<?php

namespace B2pweb\Jwt;

use BadMethodCallException;

use function json_encode;

/**
 * Base implements for store claims
 */
class Claims implements ClaimsInterface
{
    /**
     * @var array<string, mixed>
     */
    protected $claims = [];

    /**
     * Flags for json_encode
     *
     * @var int
     */
    protected $encodingFlags = JSON_UNESCAPED_SLASHES;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
    }

    /**
     * {@inheritdoc}
     */
    final public function toArray(): array
    {
        return $this->claims;
    }

    /**
     * {@inheritdoc}
     */
    final public function toJson(): string
    {
        return json_encode($this->claims, $this->encodingFlags);
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetExists($offset): bool
    {
        return isset($this->claims[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    #[\ReturnTypeWillChange]
    final public function offsetGet($offset)
    {
        return $this->claims[$offset];
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetSet($offset, $value): void
    {
        // Disallow `$claims[] = xxx` operation
        if ($offset === null) {
            throw new BadMethodCallException('Cannot use array push operator `$claims[] = $x` on ' . static::class);
        }

        $this->claims[$offset] = $value;
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetUnset($offset): void
    {
        unset($this->claims[$offset]);
    }

    /**
     * Get a claim value
     *
     * @param string $name The claim name
     * @param mixed $default The default value to use when the claim is not defined
     *
     * @return mixed The claim value
     */
    final public function claim(string $name, $default = null)
    {
        return $this->claims[$name] ?? $default;
    }
}
