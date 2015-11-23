<?php

namespace Phramework\Authentication\BasicAuthentication;

use \Phramework\Phramework;

class BasicAuthenticationTest extends \PHPUnit_Framework_TestCase
{
    protected static $users = [];

    public static function getByEmailWithPassword($email)
    {
        //Search in defiened users by email
        $users = array_filter(
            self::$users,
            function ($user) use ($email) {
                return ($user['email'] == $email);
            }
        );

        if (count($users) == 0) {
            return false;
        }

        return $users[0];
    }

    /**
     * @var BasicAuthentication
     */
    private $object;
    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
        $this->object = new BasicAuthentication();
        //NOTE, in order testAuthenticateSuccess to work all users must
        //have this password
        self::$users = [
            [
                'id' => 1,
                'email' => 'nohponex@gmail.com',
                'password' => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'user'
            ],
            [
                'id' => 2,
                'email' => 'xenofon@auth.gr',
                'password' => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'moderator'
            ],
        ];

        //Initliaze Phramework
        $phramework = new Phramework(
            [],
            (new \Phramework\URIStrategy\URITemplate([]))
        );

        //Set authentication class
        \Phramework\Authentication\Manager::register(
            BasicAuthentication::class
        );

        //Set method to fetch user object, including password attribute
        \Phramework\Authentication\Manager::setUserGetByEmailMethod(
            [BasicAuthenticationTest::class, 'getByEmailWithPassword']
        );

        \Phramework\Authentication\Manager::setAttributes(
            ['user_type', 'email']
        );

        \Phramework\Authentication\Manager::setOnAuthenticateCallback(
            /**
             * @param object $data User data object
             */
            function ($data) {
                //var_dump($params);
            }
        );
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown()
    {

    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::check
     */
    public function testCheckFailure()
    {
        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            []
        ), 'Expect false, since Authorization header is not provided');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer ABCDEF']
        ), 'Expect false, since Authorization header is not Basic');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Basic fsdfser43gfdgdfgdfgdfgdf']
        ), 'Expect false, since token makes no sense');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            [
                'Authorization' => 'Basic zm9ocG9uZXsg6MTIzNDU2Nzh4WA=='
            ]
        ), 'Expect false, since token is not correct');
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::testProvidedMethod
     */
    public function testTestProvidedMethodFailure()
    {
        $this->assertFalse($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            []
        ), 'Expect false, since Authorization header is not provided');

        $this->assertFalse($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer ABCDEF']
        ), 'Expect false, since Authorization header is not Basic');
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::testProvidedMethod
     */
    public function testTestProvidedMethodSuccess()
    {
        $this->assertTrue($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Basic zm9ocG9uZXsg6MTIzNDU2Nzh4WA==']
        ), 'Expect true, even though credentials are not correct');
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::authenticate
     * @expectedException Exception
     */
    public function testAuthenticateExpectException()
    {
        $this->object->authenticate(
            [
                'email' => 'wrongEmailType',
                'password' => '123456'
            ],
            [Phramework::METHOD_POST],
            []
        );
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::authenticate
     */
    public function testAuthenticateFailure()
    {
        $this->assertFalse(
            $this->object->authenticate(
                [
                    'email' => 'not@found.com',
                    'password' => '123456'
                ],
                Phramework::METHOD_POST,
                []
            ),
            'Expect false, sinse user email doesn`t exist'
        );

        $this->assertFalse(
            $this->object->authenticate(
                [
                    'email' => self::$users[0]['email'],
                    'password' => 'wrong'
                ],
                Phramework::METHOD_POST,
                []
            ),
            'Expect false, sinse user password is wrong'
        );
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::authenticate
     */
    public function testAuthenticateSuccess()
    {
        //Pick a random user index
        $index = 0; //rand(0, count(self::$users) - 1);

        $token = $this->object->authenticate(
            [
                'email' => self::$users[$index]['email'],
                'password' => '123456' //Since password is the same for all of them
            ],
            Phramework::METHOD_POST,
            []
        );

        $this->assertInternalType('object', $token);
    }

    /**
     * @covers Phramework\Authentication\BasicAuthentication\BasicAuthentication::check
     */
    public function testCheckSuccess()
    {
        $index = 0;

        $user = \Phramework\Authentication\Manager::check(
            [],
            Phramework::METHOD_GET,
            [
                'Authorization' => 'Basic ' . base64_encode(
                    self::$users[$index]['email'] . ':' . '123456'
                )
            ]
        );

        $this->assertInternalType('object', $user, 'Expect an object');

        $this->assertObjectHasAttribute('id', $user);
        $this->assertObjectHasAttribute('email', $user);
        $this->assertObjectHasAttribute('user_type', $user);
        $this->assertObjectNotHasAttribute('password', $user);

        $this->assertSame(self::$users[$index]['id'], $user->id);
        $this->assertSame(self::$users[$index]['email'], $user->email);
        $this->assertSame(self::$users[$index]['user_type'], $user->user_type);
    }
}
