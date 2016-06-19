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

use Phramework\Authentication\UserSession;
use Phramework\Authentication\Manager;
use Phramework\Authentication\Authentication;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * BasicAuthentication authentication implementation for phramework
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @author Xenofon Spafaridis <nohponex@gmail.com>
 * @uses password_verify to verify user's password
 * @since 0.0.0
 */
class BasicAuthentication extends Authentication
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        callable $next
    ) : ResponseInterface {
        $test = static::testProvidedMethod($request);

        if ($test === null) {
            goto ret;
        }

        list($identity, $password) = $test;

        $callback = Manager::getUserSessionCallback();

        /**
         * @var UserSession|null
         */
        $userSession = $callback($identity);

        if ($userSession === null) {
            goto ret;
        }

        if (!password_verify($password, $userSession->getPassword())) {
            goto ret;
        }

        $userSession->clearPassword();

        //Add userSession object to session attribute
        $request = $request->withAttribute('session', $userSession);

        ret:
        return $next($request, $response);
    }

    /**
     * @param ServerRequestInterface $request
     * @return string[]|null
     */
    protected static function testProvidedMethod(
        ServerRequestInterface $request
    ) {
        $header = $request->getHeader('Authorization');

        foreach ($header as $line) {
            list($token) = sscanf($line, 'Basic %s');

            if (!$token) {
                continue;
            }

            $tokenDecoded = base64_decode($token);
            $tokenParts = explode(':', $tokenDecoded);

            if (count($tokenParts) !== 2) {
                continue;
            }

            /*$identity = $tokenParts[0];
            $password = $tokenParts[1];*/

            return $tokenParts;
        }

        return null;
    }
}
