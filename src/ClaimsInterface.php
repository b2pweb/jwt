<?php

namespace B2pweb\Jwt;

use ArrayAccess;

/**
 * Base type for storing claims
 * Use this interface to customize the claims serialization
 *
 * @implements ArrayAccess<string, mixed>
 */
interface ClaimsInterface extends ArrayAccess
{
    /**
     * Export all claims to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /**
     * Export all claims to a JSON string
     *
     * @return string
     */
    public function toJson(): string;
}
