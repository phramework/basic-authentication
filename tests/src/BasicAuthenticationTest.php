<?php
/**
 * Copyright 2015-2016 Xenofon Spafaridis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace Phramework\Authentication\BasicAuthentication;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Phramework\Authentication\Manager;
use Phramework\Authentication\UserSession;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @coversDefaultClass Phramework\Authentication\BasicAuthentication\BasicAuthentication
 */
class BasicAuthenticationTest extends \PHPUnit_Framework_TestCase
{
    protected static $users = [];
    /**
     * @var ServerRequestInterface
     */
    protected $request;
    /**
     * @var ResponseInterface
     */
    protected $response;

    /**
     * @param string $identity use email as identity
     * @return null|UserSession
     */
    public static function getByEmailWithPassword(string $identity)
    {
        //Search in defined users by email
        $users = array_values(array_filter(
            self::$users,
            function ($user) use ($identity) {
                return ($user['email'] == $identity);
            }
        ));

        if (count($users) === 0) {
            return null;
        }

        return new UserSession(
            $users[0]['id'],
            $users[0]['password'],
            $users[0]['user_type'],
            (object) [
                'email' => $users[0]['email']
            ]
        );
    }

    public static function setUpBeforeClass()
    {
        //NOTE, in order testAuthenticateSuccess to work all users must
        //have this password
        self::$users = [
            [
                'id'        => '1',
                'email'     => 'nohponex@gmail.com',
                'password'  => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'user'
            ],
            [
                'id'        => '2',
                'email'     => 'nohponex+json@gmail.com',
                'password'  => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'moderator'
            ],
        ];

        //Set method to fetch user object, including password attribute
        Manager::setUserSessionCallback(
            [BasicAuthenticationTest::class, 'getByEmailWithPassword']
        );
    }

    public function setUp()
    {
        $this->request  = new ServerRequest('GET', 'http://localhost/');
        $this->response = new Response();
    }

    /**
     * @covers ::__invoke
     */
    public function testInvokeNotSet()
    {
        $next = function (
            ServerRequestInterface $request,
            ResponseInterface $response
        ) {
            static::assertNull(
                $request->getAttribute('session')
            );

            return $response;
        };

        $authentication = new BasicAuthentication();

        $authentication(
            $this->request,
            $this->response,
            $next
        );
    }

    public function invokeInvalidOrUnrelated()
    {
        return [
            ['ABCD xxxx'], //doesn't start with basic
            ['Basic ' . base64_encode('xxxyyyzzz')], //not with two parts
            ['Basic ' . base64_encode('some@mail.com:password')], //not with two parts
            ['Basic ' . base64_encode('nohponex@gmail.com:xxx')] //wrong password
        ];
    }

    /**
     * @covers ::__invoke
     * @dataProvider invokeInvalidOrUnrelated
     */
    public function testInvokeInvalidOrUnrelated(string $header)
    {
        $next = function (
            ServerRequestInterface $request,
            ResponseInterface $response
        ) {
            static::assertNull($request->getAttribute('session'));

            return $response;
        };

        $authentication = new BasicAuthentication();

        $authentication(
            (
                $this->request
                    ->withHeader('Authorization', $header)
            ),
            $this->response,
            $next
        );
    }

    public function invokeSuccess()
    {
        return [
            ['Basic ' . base64_encode('nohponex+json@gmail.com:123456'), '2'],
            ['Basic ' . base64_encode('nohponex@gmail.com:123456'),      '1']
        ];
    }

    /**
     * @covers ::__invoke
     * @dataProvider invokeSuccess
     */
    public function testInvokeSuccess(string $header, string $identity)
    {
        $next = function (
            ServerRequestInterface $request,
            ResponseInterface $response
        ) use ($identity) {
            $session = $request->getAttribute('session');

            static::assertInstanceOf(UserSession::class, $session);

            static::assertSame(
                $identity,
                $session->getId()
            );

            //defined by our getByEmailWithPassword
            static::assertObjectHasAttribute(
                'email',
                $session->getAttributes()
            );

            return $response;
        };

        $authentication = new BasicAuthentication();

        $authentication(
            (
                $this->request
                    ->withHeader('Authorization', $header)
            ),
            $this->response,
            $next
        );
    }

    /**
     * @covers ::testProvidedMethod
     * @dataProvider invokeInvalidOrUnrelated
     */
    public function testInvoke(string $header)
    {
        return $this->testInvokeInvalidOrUnrelated($header);
    }
    /**
     * @covers ::testProvidedMethod
     * @dataProvider invokeSuccess
     */
    public function testMethodSuccess(string $header, string $identity)
    {
        return $this->testInvokeSuccess($header, $identity);
    }
}
