<?php

namespace BenjaminStout\Crypt\lib;

use BenjaminStout\Crypt\Config;

class Sodium implements CryptInterface
{
    /**
     * Cryptography library name associated with this class
     *
     * @access private
     */
    private $libName = 'Sodium';

    /**
     * Constructor
     *
     * @throws \Exception extension unloaded
     * @access public
     */
    public function __construct()
    {
        if (!extension_loaded('sodium') && !extension_loaded('libsodium')) {
            throw new \Exception("Sodium->__construct(): Sodium PHP extension is not loaded.");
        }
    }

    /**
     * Generates and returns a randomly-generated encryption key
     * Uses random_compat for random_bytes() if PHP < 7
     *
     * @return string $key
     * @access public
     */
    public function generateKey()
    {
        return random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * Validates encryption key against a set of library-specific rules
     *
     * @param string $key
     * @return bool valid, else
     * @throws \Exception invalid
     * @access public
     */
    public function validateKey($key = null)
    {
        if (mb_strlen($key, '8bit') != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \Exception('Sodium->validateKey(): Invalid key length, must be ' . SODIUM_CRYPTO_SECRETBOX_KEYBYTES . ' bytes long.');
        }
        return true;
    }

    /**
     * Encrypts (and base64 encodes) using Sodium encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     */
    public function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = $nonce . sodium_crypto_secretbox($plaintext, $nonce, Config::read("key{$this->libName}"));

        if (!empty($base64)) {
            $cipher = base64_encode($cipher);
        }

        sodium_memzero($plaintext);

        return $cipher;
    }

    /**
     * Decrypts (and optionally converts from base64) using sodium decryption
     *
     * @param string $cipher
     * @param bool $base64 [true]
     * @return string $plaintext
     * @throws \Exception unable to decode/decrypt
     * @access public
     */
    public function decrypt($cipher, $base64 = true)
    {
        if (!empty($base64)) {
            $cipher = base64_decode($cipher);
            if ($cipher === false) {
                throw new \Exception('Crypto::decrypt_sodium [ERROR]: Invalid base 64 string, unable to decode ciphertext.');
            }
            if (mb_strlen($cipher, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
                throw new \Exception('Crypto::decrypt_sodium [ERROR]: Ciphertext truncated, unable to decrypt.');
            }
        }

        $nonce = mb_substr($cipher, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($cipher, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, Config::read("key{$this->libName}"));
        if ($plaintext === false) {
             throw new \Exception('Crypto::decrypt_sodium [ERROR]: Ciphertext has been tampered with, decryption failed.');
        }

        sodium_memzero($ciphertext);
        sodium_memzero($cipher);

        return $plaintext;
    }
}
