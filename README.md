# PHP-Crypt
<img src="https://img.shields.io/travis/com/benjaminstout/php-crypt/master.svg?style=flat-square" alt="build:"> <img src="https://img.shields.io/github/languages/code-size/benjaminstout/php-crypt.svg?style=flat-square"> <img src="https://img.shields.io/github/license/benjaminstout/php-crypt.svg?color=%23307ABE&style=flat-square"> <img src="https://img.shields.io/github/downloads/benjaminstout/php-crypt/total.svg?style=flat-square">

A standalone, extensible, lightweight cryptography library for PHP, with support for libsodium (NaCl), OpenSSL, Mcrypt, and more.

PHP-Crypt allows you to quickly integrate a suite of modern cryptographic libraries into your PHP application, without the hassle of implementing advanced custom cryptographic methods by hand. PHP-Crypt prevents common cryptographic pitfalls, while providing the flexibility to choose between a suite of the latest cryptography libraries available for PHP. Usage is straightforward and highly extensible – comprised only of the minimum complexity necessary to ensure optimal security. PHP-Crypt makes swapping or integrating new cryptography libraries a breeze!

PHP-Crypt features [*authenticated encryption*](https://en.wikipedia.org/wiki/Authenticated_encryption) straight out of the box (with a supported library – [Sodium](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption), [OpenSSL](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption), etc.)

PHP-Crypt is easily extensible – just drop an implementation of your favorite cryptography library into src/lib, and call `new Crypt('<yourClass>')` when instantiating PHP-Crypt. It couldn't be easier! While you're at it, [submit a PR](https://github.com/benjaminstout/php-crypt/pull/new/master) with your shiny new library!


## Installation

__Git__: `git add submodule git@github.com:benjaminstout/php-crypt.git <path/to/folder>`  
__Composer__: `composer require benjaminstout/php-crypt`

If using with CakePHP, don't forget to add `Plugin::load('BenjaminStout/Crypt')` to your `bootstrap.php`.


## Getting Started

__Instantiate a new instance__:  
```php
$this->Crypt = new Crypt('<library>', '<key>');
```
*Where*:  
`<library>` is the cryptography library to use (Sodium [default], OpenSsl, Mcrypt, ...)  
`<key>` is an optional key to use for encryption.

__Encrypt a string__:  
```php
$this->Crypt::encrypt('string');
```

__Decrypt a cipher__:  
```php
$this->Crypt::decrypt('eNcRyPtEd');
```


*__Note__*: If `<key>` is left unspecified during instantiation, php-crypt will look for an existing key located first at `Config::$config['key<library>']` and then `Config::$config['keyPath']`. If no existing key is found, it automatically generates a suitable random key to use for the library. See [encryption keys](#encryption-keys) for more info.


## Encryption Keys

For security purposes, keys are stored in the filesystem well outside of WWW_ROOT by default. Existing key files should be __lowercase__, with a suffix of `.key`, and named after the library to which they belong. Ex: `keyOpenSsl => 'openssl.key'`. 

Passing a key into the constructor will create an alternate `.custom.key` file (to avoid overwriting pre-existing keys). For example:
```php
$this->Crypt = new Crypt('OpenSsl', 'KeY123');
```
Would create a file under `Config::$config['keyPath']` named openssl.custom.key with the contents `KeY123`. Just – please don't use this key...


## Testing

Run a `composer update --dev` to install phpunit in the project, then run `vendor/bin/phpunit` from the root of the project.


## Contributing

All contributions are welcome and encouraged! Start a discussion by [opening an issue](https://github.com/benjaminstout/php-crypt/issues/new), then fork this repo, commit your work, and [submit a PR](https://github.com/benjaminstout/php-crypt/pull/new/master)!


## Important Notes

Use of the Mcrypt library is *__highly__* disadvised, and is only included in PHP-Crypt for backwards compatability. The underlying library (libmcrypt) has been abandoned since 2007, and contains a host of undesirable behaviors and possible vulnerabilities. Instead, use Sodium or OpenSSL.


## License

This project is licensed under the terms of the [MIT license](LICENSE.md).
