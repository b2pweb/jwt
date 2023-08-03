<?php

namespace B2pweb\Jwt\Tests;

use B2pweb\Jwt\JWT;
use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function test_fromJwtUnsafe_success()
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $decoded = JWT::fromJwtUnsafe($jwt);

        $this->assertSame(['alg' => 'HS256', 'typ' => 'JWT'], $decoded->headers());
        $this->assertSame(['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022], $decoded->payload());
        $this->assertSame($jwt, $decoded->encoded());
    }

    public function test_fromJwtUnsafe_missing_parts()
    {
        $this->expectException(\InvalidArgumentException::class);
        JWT::fromJwtUnsafe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
    }

    public function test_fromJwtUnsafe_header_not_base64()
    {
        $this->expectException(\InvalidArgumentException::class);
        $jwt = '###.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        JWT::fromJwtUnsafe($jwt);
    }

    public function test_fromJwtUnsafe_payload_not_base64()
    {
        $this->expectException(\InvalidArgumentException::class);
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.###.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        JWT::fromJwtUnsafe($jwt);
    }

    public function test_fromJwtUnsafe_header_not_valid_json()
    {
        $this->expectException(\InvalidArgumentException::class);
        $jwt = 'MTIz.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        JWT::fromJwtUnsafe($jwt);
    }

    public function test_fromJwtUnsafe_payload_not_valid_json()
    {
        $this->expectException(\InvalidArgumentException::class);
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MTIz.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        JWT::fromJwtUnsafe($jwt);
    }
}
