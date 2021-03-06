<?php
/**
 * Copyright 2015 Xenofon Spafaridis
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

use \Phramework\Phramework;
use \Phramework\Authentication\Manager;

/**
 * BasicAuthentication authentication implementation for phramework
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @author Xenofon Spafaridis <nohponex@gmail.com>
 * @uses password_verify to verify user's password
 *
 */
class BasicAuthentication implements \Phramework\Authentication\IAuthentication
{

    /**
     * Test if current request holds authorization data
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return boolean
     */
    public function testProvidedMethod($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($token) = sscanf($headers['Authorization'], 'Basic %s');

        if (!$token) {
            return false;
        }

        return true;
    }

    /**
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return object|FALSE Returns false on error or the user object on success
     */
    public function check($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($token) = sscanf($headers['Authorization'], 'Basic %s');

        if (!$token) {
            return false;
        }

        $tokenDecoded = base64_decode($token);

        $tokenParts = explode(':', $tokenDecoded);

        if (count($tokenParts) != 2) {
            return false;
        }

        $email    = \Phramework\Validate\EmailValidator::parseStatic($tokenParts[0]);
        $password = $tokenParts[1];

        list($user) = $this->authenticate(
            [
                'email' => $email,
                'password' => $password,
            ],
            $method,
            $headers
        );

        if ($user !== false && ($callback = Manager::getOnCheckCallback()) !== null) {
            call_user_func(
                $callback,
                $user
            );
        }

        return $user;
    }

    /**
     * Authenticate a user using JWT authentication method
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return false|array  Returns false on failure
     */
    public function authenticate($params, $method, $headers)
    {
        $email = \Phramework\Validate\EmailValidator::parseStatic($params['email']);
        $password = $params['password'];

        $user = call_user_func(Manager::getUserGetByEmailMethod(), $email);

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password'])) {
            return false;
        }

        /*
         * Create the token as an array
        */
        $data = [
            'id' => $user['id']
        ];

        //copy user attributes to jwt's data
        foreach (Manager::getAttributes() as $attribute) {
            if (!isset($user[$attribute])) {
                throw new \Phramework\Exceptions\ServerException(sprintf(
                    'Attribute "%s" is not set in user object',
                    $attribute
                ));
            }
            $data[$attribute] = $user[$attribute];
        }

        //Convert to object
        $data = (object)$data;

        //Call onAuthenticate callback if set
        if (($callback = Manager::getOnAuthenticateCallback()) !== null) {
            call_user_func(
                $callback,
                $data
            );
        }

        return [$data];
    }
}
