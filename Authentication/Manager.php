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
namespace Phramework\Authentication;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Authentication manager
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @author Xenofon Spafaridis <nohponex@gmail.com>
 * @since 1.0.0
 */
final class Manager
{
    /**
     * @var callable
     */
    protected static $userSessionCallback;

    /**
     * Set method callback used to fetch a user by his unique identity
     * @param callable $callback The callback should accept string $identity
     *     and return a UserSession object or null if user by this identity is not found.
     *     Returned object's password will be used to verify user's password
     *     against the provided password, password must be stored in a supported method
     *     in order Authentication methods to be able to use it. The use of
     *     password_hash is suggested for compatibility across all implementations.
     *
     */
    public static function setUserSessionCallback(callable $callback)
    {
        static::$userSessionCallback = $callback;
    }

    /**
     * @param string $identity
     * @return UserSession|null
     */
    public static function callUserSessionCallback(string $identity)
    {
        if (static::$userSessionCallback === null) {
            //return an empty callable with return value null
            return null;
        }

        $callback = static::$userSessionCallback;

        return $callback($identity);
    }

    /**
     * Store session attribute containing the UserSession object at request
     * @param ServerRequestInterface $request
     * @param UserSession            $session
     * @return ServerRequestInterface
     */
    public static function storeAttributes(
        ServerRequestInterface $request,
        UserSession $session
    ) : ServerRequestInterface {
        //Clear password for increased security against data leakage
        $session->clearPassword();

        //Add userSession object to session attribute
        return $request->withAttribute('session', $session);
    }
}
