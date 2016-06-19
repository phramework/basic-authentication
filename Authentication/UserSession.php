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

/**
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @author Xenofon Spafaridis <nohponex@gmail.com>
 * @since 1.0.0
 */
class UserSession
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string|null
     */
    protected $password;

    /**
     * @var string
     */
    protected $level;

    /**
     * @var \stdClass
     */
    protected $attributes;

    public function __construct(
        string $id,
        string $password,
        string $level = null,
        \stdClass $attributes = null
    ) {
        $this->id       = $id;
        $this->password = $password;
        $this->level    = $level;
        $this->attributes = $attributes ?? new \stdClass();
    }

    /**
     * @return string
     */
    public function getId() : string
    {
        return $this->id;
    }

    /**
     * @return string|null
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @return string|null
     */
    public function getLevel()
    {
        return $this->level;
    }

    /**
     * @return \stdClass
     */
    public function getAttributes() : \stdClass
    {
        return $this->attributes;
    }

    public function clearPassword()
    {
        $this->password = null;
    }

}
