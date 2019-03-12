# PHP-Crypt
<a href="https://travis-ci.com/benjaminstout/php-crypt"><img src="https://img.shields.io/travis/com/benjaminstout/php-crypt/master.svg?style=flat-square" alt="build:"></a> <img src="https://img.shields.io/github/languages/code-size/benjaminstout/php-crypt.svg?style=flat-square"> <img src="https://img.shields.io/github/license/benjaminstout/php-crypt.svg?color=%23307ABE&style=flat-square"> <img src="https://img.shields.io/github/downloads/benjaminstout/php-crypt/total.svg?style=flat-square">

A standalone, extensible, lightweight cryptography interface for PHP. With support for: [libsodium](https://github.com/jedisct1/libsodium) (NaCl), [OpenSSL](http://php.net/manual/en/book.openssl.php), [Mcrypt](http://php.net/manual/en/book.mcrypt.php), and more.

PHP-Crypt allows you to quickly integrate a suite of modern cryptographic libraries into your PHP application, without the hassle of implementing advanced custom cryptographic methods by hand. PHP-Crypt prevents common cryptographic pitfalls, while providing the flexibility to choose between a suite of the latest cryptography libraries available for PHP. Usage is straightforward and highly extensible – comprised only of the minimum complexity necessary to ensure optimal security. PHP-Crypt makes swapping or integrating new cryptography libraries a breeze!

* PHP-Crypt features [*authenticated encryption*](https://en.wikipedia.org/wiki/Authenticated_encryption) straight out of the box (with [Sodium](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption) or [OpenSSL](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption))

* PHP-Crypt is easily extensible – just drop an implementation of your favorite cryptography library into src/lib, and call `new Crypt('<yourClass>')` when instantiating PHP-Crypt. It couldn't be easier! While you're at it, [submit a PR](https://github.com/benjaminstout/php-crypt/pull/new/master)!

## Prerequisites

* PHP >= 5.6
* If on PHP < 7.2, and you would like to use the Sodium library, make sure to [install libsodium and the sodium PHP extension](https://paragonie.com/book/pecl-libsodium/read/00-intro.md).

## Installation

PHP-Crypt supports installation in your PHP app through either [composer](https://getcomposer.org/) or [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules).

__Composer__: `composer require benjaminstout/php-crypt`  
__Git__: `git add submodule git@github.com:benjaminstout/php-crypt.git <path/to/folder>`

*__Note__*: If using with CakePHP, don't forget to add `Plugin::load('BenjaminStout/Crypt')` to your `bootstrap.php`.


## Getting Started

__Instantiate a new instance of PHP-Crypt__:  
```php
$this->Crypt = new Crypt('<library>', ['key' => '<key>']);
```
*Where*:  
`<library>` is the cryptography library to use (Sodium [default], Openssl, Mcrypt, ...)  
`<key>` is an optional key to use for encryption.

__Encrypt a string__:  
```php
$this->Crypt::encrypt('string');
```

__Decrypt ciphertext__:  
```php
$this->Crypt::decrypt('eNcRyPtEd');
```


## Encryption Keys

If the encryption key is left unspecified during instantiation, PHP-Crypt will look for an existing key located first at `Config::$config['keyPath<library>']` and then `Config::$config['keyPath']`. If no existing key is found, PHP-Crypt automatically generates and saves a suitable random key for use by the library.

For security purposes, keys are stored in the filesystem well outside of WWW_ROOT by default. Existing key files should be __lowercase__, with a suffix of `.key`, and named after the library to which they belong. Ex: `keyPathOpenssl => 'openssl.key'`. 

### *Examples*:

* Allowing PHP-Crypt to generate your keys for you without any pre-existing key file:
  ```php
  $this->Crypt = new Crypt('Openssl');
  ```  
  automatically saves the generated random key to `openssl.key` under `Config::$config['keyPath']`.

* Whereas, passing a key into the constructor will create an alternate `.custom.key` file (to avoid overwriting pre-existing keys). For example:
  ```php
  $this->Crypt = new Crypt('Openssl', 'KeY123');
  ```
  Creates a file under `Config::$config['keyPath']` named openssl.custom.key with the contents `KeY123`.

* If you wish to specify a unique path to a key for a library to use, pass in a value for `'keyPath<library>'` during instantiation:
  ```php
  $this->Crypt = new Crypt('Openssl', [
      'keyPathOpenssl' => '/path/to/openssl.key',
  ]);
  ```
  or, set it afterwards:
  ```php
  Crypt::setPath('Openssl', '/path/to/openssl.key');
  ```


## Testing

Run a `composer update --dev` to install phpunit in the project, then run `vendor/bin/phpunit` from the root of the project.


## Contributing

All contributions are welcome and encouraged! Start a discussion by [opening an issue](https://github.com/benjaminstout/php-crypt/issues/new), then fork this repo, commit your work, and [submit a PR](https://github.com/benjaminstout/php-crypt/pull/new/master)!


## Important Notes

Use of the Mcrypt library is *__highly__* disadvised, and is only included in PHP-Crypt for backwards compatability. The underlying library (libmcrypt) has been abandoned since 2007, and contains a host of undesirable behaviors and possible vulnerabilities. Instead, use Sodium or OpenSSL.


## License

This project is licensed under the terms of the [MIT license](LICENSE.md).
