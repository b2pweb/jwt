<?php

namespace B2pweb\Jwt;

use InvalidArgumentException;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

/**
 * Handle JSON Web Algorithms
 *
 * @see https://tools.ietf.org/html/rfc7518
 */
final class JWA
{
    public const TYPE_HMAC = 'hmac';
    public const TYPE_RSA = 'rsa';
    public const TYPE_ELLIPTIC_CURVE = 'ec';
    public const TYPE_RSASSA_PSS = 'rsassa-pss';
    public const TYPE_NONE = 'none';

    /**
     * Maps the alg header value to algorithm information
     *
     * Keys :
     * - class : The class name of the algorithm
     * - hash  : The hash function used by the algorithm
     * - type  : The algorithm type
     *
     * @var array<string, array{class: class-string<Algorithm>, hash?: string, type: JWA::TYPE_*}>
     */
    private $algMap = [
        // HMAC : https://tools.ietf.org/html/rfc7518#section-3.2
        'HS256' => ['class' => HS256::class, 'hash' => 'sha256', 'type' => self::TYPE_HMAC],
        'HS384' => ['class' => HS384::class, 'hash' => 'sha384', 'type' => self::TYPE_HMAC],
        'HS512' => ['class' => HS512::class, 'hash' => 'sha512', 'type' => self::TYPE_HMAC],

        // RSA : https://tools.ietf.org/html/rfc7518#section-3.3
        'RS256' => ['class' => RS256::class, 'hash' => 'sha256', 'type' => self::TYPE_RSA],
        'RS384' => ['class' => RS384::class, 'hash' => 'sha384', 'type' => self::TYPE_RSA],
        'RS512' => ['class' => RS512::class, 'hash' => 'sha512', 'type' => self::TYPE_RSA],

        // ECDSA : https://tools.ietf.org/html/rfc7518#section-3.4
        'ES256' => ['class' => ES256::class, 'hash' => 'sha256', 'type' => self::TYPE_ELLIPTIC_CURVE],
        'ES384' => ['class' => ES384::class, 'hash' => 'sha384', 'type' => self::TYPE_ELLIPTIC_CURVE],
        'ES512' => ['class' => ES512::class, 'hash' => 'sha512', 'type' => self::TYPE_ELLIPTIC_CURVE],

        // RSASSA-PSS : https://tools.ietf.org/html/rfc7518#section-3.5
        'PS256' => ['class' => PS256::class, 'hash' => 'sha256', 'type' => self::TYPE_RSASSA_PSS],
        'PS384' => ['class' => PS384::class, 'hash' => 'sha384', 'type' => self::TYPE_RSASSA_PSS],
        'PS512' => ['class' => PS512::class, 'hash' => 'sha512', 'type' => self::TYPE_RSASSA_PSS],

        // Unsecure : https://tools.ietf.org/html/rfc7518#section-3.6
        'none' => ['class' => None::class, 'type' => self::TYPE_NONE],
    ];

    /**
     * Map of enabled algorithms
     *
     * @var array<string, bool>
     */
    private $enabled = [
        'HS256' => true,
        'HS384' => true,
        'HS512' => true,
        'RS256' => true,
        'RS384' => true,
        'RS512' => true,
        'ES256' => true,
        'ES384' => true,
        'ES512' => true,
        'PS256' => true,
        'PS384' => true,
        'PS512' => true,
    ];

    /**
     * @var AlgorithmManager|null
     */
    private $manager;

    /**
     * Get list of algorithms identifiers (alg header parameter) for a given type
     *
     * @param string $type One of the JWA::TYPE_ constant
     *
     * @return string[]
     */
    public function algorithmsByType(string $type): array
    {
        $algorithms = [];

        foreach ($this->enabled as $id => $enabled) {
            if ($enabled && $this->algMap[$id]['type'] === $type) {
                $algorithms[] = $id;
            }
        }

        return $algorithms;
    }

    /**
     * Get the hash algorithm used by the given alg
     *
     * @param string $alg The "alg" header parameter
     *
     * @return string The hash algorithm
     *
     * @throws InvalidArgumentException When an unsupported alg is given
     */
    public function hashAlgorithm(string $alg): string
    {
        if (empty($this->enabled[$alg]) || empty($this->algMap[$alg]['hash'])) {
            throw new InvalidArgumentException('Unsupported alg "' . $alg . '"');
        }

        return $this->algMap[$alg]['hash'];
    }

    /**
     * Enable (or disable) an algorithm
     *
     * @param string $alg The alg id
     * @param bool $value Enable ?
     *
     * @return $this
     */
    public function enable(string $alg, bool $value = true): self
    {
        if (!isset($this->algMap[$alg]) || !class_exists($this->algMap[$alg]['class'])) {
            throw new InvalidArgumentException('Unsupported alg "' . $alg . '"');
        }

        $this->enabled[$alg] = $value;
        $this->manager = null;

        return $this;
    }

    /**
     * Filter the algorithms, and returns a new instance of JWA representing the subset of algorithms
     * This method will not modify the current instance
     *
     * @param string[] $algorithms List of algorithms to keep
     *
     * @return self The new instance
     */
    public function filter(array $algorithms): self
    {
        $jwa = clone $this;

        $algorithms = array_flip($algorithms);

        // Enable intersection of already enabled algorithms with $algorithms
        foreach ($jwa->enabled as $alg => $enabled) {
            $jwa->enabled[$alg] = $enabled && isset($algorithms[$alg]);
        }

        // A manager is already instantiated : filters enabled algorithms and recreates a new manager
        if ($jwa->manager) {
            $algorithms = [];

            foreach ($jwa->enabled as $alg => $enabled) {
                if ($enabled && $jwa->manager->has($alg)) {
                    $algorithms[] = $jwa->manager->get($alg);
                }
            }

            $jwa->manager = new AlgorithmManager($algorithms);
        }

        return $jwa;
    }

    /**
     * Get the algorithm manager
     *
     * @return AlgorithmManager
     */
    public function manager(): AlgorithmManager
    {
        if ($this->manager !== null) {
            return $this->manager;
        }

        $algorithms = [];

        foreach ($this->enabled as $id => $enabled) {
            if ($enabled) {
                $className = $this->algMap[$id]['class'];

                if (class_exists($className)) {
                    $algorithms[] = new $className();
                }
            }
        }

        return $this->manager = new AlgorithmManager($algorithms);
    }

    /**
     * Register a new algorithm
     *
     * @param string $alg The "alg" header parameter
     * @param class-string<Algorithm> $class The algorithm implementation class
     * @param JWA::TYPE_* $type The algorithm type
     * @param string|null $hash The hash function
     */
    public function register(string $alg, string $class, string $type, ?string $hash = null): void
    {
        $this->algMap[$alg] = ['class' => $class, 'type' => $type];

        if ($hash) {
            $this->algMap[$alg]['hash'] = $hash;
        }
    }
}
