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
 * @since 1.0.0
 */
class BasicAuthentication extends Authentication
{
    /**
     * Middleware handler
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param callable               $next
     * @return ResponseInterface
     */
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        callable $next
    ) : ResponseInterface {
        $test = static::extractAuthentication($request);

        if ($test === null) {
            goto ret;
        }

        list($identity, $password) = $test;

        $userSession = Manager::callUserSessionCallback($identity);

        if ($userSession === null) {
            goto ret;
        }

        if (!password_verify($password, $userSession->getPassword())) {
            goto ret;
        }

        //Store attribute at request
        $request = Manager::storeAttributes($request, $userSession);

        ret:
        return $next($request, $response);
    }

    /**
     * Extract identity and password from request
     * @param ServerRequestInterface $request
     * @return string[]|null On success returns [$identity, $password] else null
     */
    protected static function extractAuthentication(
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
