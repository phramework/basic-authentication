# phramework/basic-authentication
Basic authentication implementation for phramework

[![Build Status](https://travis-ci.org/phramework/basic-authentication.svg?branch=master)](https://travis-ci.org/phramework/basic-authentication)

## Usage
Require package

```
composer require phramework/basic-authentication
```

```php
//Set authentication class
\Phramework\Authentication\Manager::register(
    \Phramework\Authentication\BasicAuthentication\BasicAuthentication::class
);

//Set method to fetch user object, including password attribute
\Phramework\Authentication\Manager::setUserGetByEmailMethod(
    [\MyApp\API\Models\User::class, 'getByEmailWithPassword']
);

\Phramework\Authentication\Manager::setAttributes(
    ['user_type', 'email']
);
```

## Install dependencies

```bash
composer update
```

## Test and lint code

```bash
composer lint
composer test
```

# License
Copyright 2015-2016 Xenofon Spafaridis

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
