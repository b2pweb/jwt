<?php

namespace B2pweb\Jwt\Tests;

use B2pweb\Jwt\Claims;
use BadMethodCallException;
use PHPUnit\Framework\TestCase;

class ClaimsTest extends TestCase
{
    public function test_array_access()
    {
        $claims = new Claims(['foo' => 'bar']);

        $this->assertTrue(isset($claims['foo']));
        $this->assertSame('bar', $claims['foo']);
        $this->assertSame('bar', $claims->claim('foo'));
        $this->assertSame('bar', $claims->claim('foo', 'zzz'));
        $this->assertNull($claims->claim('a'));
        $this->assertSame('zzz', $claims->claim('a', 'zzz'));

        $claims['foo'] = 'baz';
        $this->assertSame('baz', $claims['foo']);

        unset($claims['foo']);
        $this->assertFalse(isset($claims['foo']));
    }

    public function test_disallow_array_push_operator()
    {
        $claims = new Claims(['foo' => 'bar']);

        $this->expectException(BadMethodCallException::class);
        $claims[] = 'baz';
    }

    public function test_toJson()
    {
        $claims = new Claims(['foo' => 'bar']);
        $this->assertSame('{"foo":"bar"}', $claims->toJson());

        $claims['iss'] = 'http://foo.bar';
        $this->assertSame('{"foo":"bar","iss":"http://foo.bar"}', $claims->toJson());

        $claims = new class(['iss' => 'http://foo.bar']) extends Claims {
            protected $encodingFlags = 0;
        };
        $this->assertSame('{"iss":"http:\/\/foo.bar"}', $claims->toJson());
    }

    public function test_toArray()
    {
        $claims = new Claims(['foo' => 'bar']);
        $this->assertSame(['foo' => 'bar'], $claims->toArray());

        $claims['iss'] = 'http://foo.bar';
        $this->assertSame(['foo' => 'bar', 'iss' => 'http://foo.bar'], $claims->toArray());
    }

    public function test_protected_properties()
    {
        $claims = new class extends Claims {
            public function test(): void
            {
                TestCase::assertTrue(isset($this->claims));
                TestCase::assertTrue(isset($this->encodingFlags));
            }
        };

        $claims->test();
    }
}
