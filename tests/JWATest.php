<?php

namespace B2pweb\Jwt\Tests;

use B2pweb\Jwt\JWA;
use PHPUnit\Framework\TestCase;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;

/**
 * Class JWATest
 */
class JWATest extends TestCase
{
    /**
     * @var JWA
     */
    private $jwa;

    protected function setUp(): void
    {
        $this->jwa = new JWA();
    }

    /**
     *
     */
    public function test_manager()
    {
        $manager = $this->jwa->manager();
        $this->assertInstanceOf(AlgorithmManager::class, $manager);
        $this->assertEquals(['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'], $manager->list());
        $this->assertSame($manager, $this->jwa->manager());

        $this->jwa
            ->enable('HS384', false)
            ->enable('RS384', false)
            ->enable('PS384', false)
            ->enable('ES384', false)
        ;

        $this->assertNotSame($manager, $this->jwa->manager());
        $this->assertEquals(['HS256', 'HS512', 'RS256', 'RS512', 'ES256', 'ES512', 'PS256', 'PS512'], $this->jwa->manager()->list());
    }

    /**
     *
     */
    public function test_hashAlgorithm_not_enabled()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported alg "HS256"');

        $this->jwa->enable('HS256', false);
        $this->jwa->hashAlgorithm('HS256');
    }

    /**
     *
     */
    public function test_hashAlgorithm_not_supported()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported alg "none"');

        $this->jwa->enable('none');
        $this->jwa->hashAlgorithm('none');
    }

    /**
     *
     */
    public function test_hashAlgorithm()
    {
        $this->assertEquals('sha256', $this->jwa->hashAlgorithm('HS256'));
        $this->assertEquals('sha256', $this->jwa->hashAlgorithm('RS256'));
        $this->assertEquals('sha256', $this->jwa->hashAlgorithm('ES256'));
        $this->assertEquals('sha256', $this->jwa->hashAlgorithm('PS256'));
        $this->assertEquals('sha384', $this->jwa->hashAlgorithm('HS384'));
        $this->assertEquals('sha384', $this->jwa->hashAlgorithm('RS384'));
        $this->assertEquals('sha384', $this->jwa->hashAlgorithm('ES384'));
        $this->assertEquals('sha384', $this->jwa->hashAlgorithm('PS384'));
        $this->assertEquals('sha512', $this->jwa->hashAlgorithm('HS512'));
        $this->assertEquals('sha512', $this->jwa->hashAlgorithm('RS512'));
        $this->assertEquals('sha512', $this->jwa->hashAlgorithm('ES512'));
        $this->assertEquals('sha512', $this->jwa->hashAlgorithm('PS512'));
    }

    /**
     *
     */
    public function test_algorithmByType()
    {
        $this->assertEquals(['HS256', 'HS384', 'HS512'], $this->jwa->algorithmsByType(JWA::TYPE_HMAC));
        $this->assertEquals(['RS256', 'RS384', 'RS512'], $this->jwa->algorithmsByType(JWA::TYPE_RSA));
        $this->assertEquals(['PS256', 'PS384', 'PS512'], $this->jwa->algorithmsByType(JWA::TYPE_RSASSA_PSS));
        $this->assertEquals(['ES256', 'ES384', 'ES512'], $this->jwa->algorithmsByType(JWA::TYPE_ELLIPTIC_CURVE));
        $this->assertEquals([], $this->jwa->algorithmsByType('not found'));
    }

    /**
     *
     */
    public function test_algorithmByType_disabled()
    {
        $this->jwa->enable('HS384', false);
        $this->assertEquals(['HS256', 'HS512'], $this->jwa->algorithmsByType(JWA::TYPE_HMAC));
    }

    /**
     *
     */
    public function test_filter()
    {
        $old = clone $this->jwa;
        $jwa = $this->jwa->filter(['HS256', 'RS512', 'none']);

        $this->assertEquals($old, $this->jwa);
        $this->assertNotSame($jwa, $this->jwa);
        $this->assertEquals(['HS256', 'RS512'], $jwa->manager()->list());
    }

    /**
     *
     */
    public function test_filter_with_already_instantiated_manager()
    {
        $manager = $this->jwa->manager();
        $jwa = $this->jwa->filter(['HS256', 'RS512', 'none']);

        $this->assertEquals(['HS256', 'RS512'], $jwa->manager()->list());
        $this->assertSame($manager->get('HS256'), $jwa->manager()->get('HS256'));
        $this->assertSame($manager->get('RS512'), $jwa->manager()->get('RS512'));
    }

    /**
     *
     */
    public function test_register()
    {
        $this->jwa->register('custom', RS256::class, 'type', 'hash');
        $this->jwa->enable('custom');

        $this->assertEquals('hash', $this->jwa->hashAlgorithm('custom'));
        $this->assertEquals(['custom'], $this->jwa->algorithmsByType('type'));
    }

    /**
     *
     */
    public function test_enable_not_available()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported alg "not found"');

        $this->jwa->enable('not found');
    }

    /**
     *
     */
    public function test_enable_class_not_exists()
    {
        $this->jwa->register('NOTFOUND', 'NotFound', JWA::TYPE_HMAC, 'sha1');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported alg "NOTFOUND"');

        $this->jwa->enable('NOTFOUND');
    }

    /**
     *
     */
    public function test_manager_with_class_not_found_should_be_filtered()
    {
        $jwa = $this->jwa->filter(['RS256', 'HS512']);
        $jwa->register('NOTFOUND', 'NotFound', JWA::TYPE_HMAC, 'sha1');

        $this->assertEquals(['HS512', 'RS256'], $jwa->manager()->list());
    }

    /**
     *
     */
    public function test_filter_should_ignore_not_found_algo_class()
    {
        $this->jwa->register('NOTFOUND', 'NotFound', JWA::TYPE_HMAC, 'sha1');
        $this->jwa->manager();
        $jwa = $this->jwa->filter(['RS256', 'HS512', 'NOTFOUND']);

        $this->assertEquals(['HS512', 'RS256'], $jwa->manager()->list());
    }
}
