<?php

namespace BenjaminStout\Crypt\lib;

use BenjaminStout\Crypt\Config;

class Openssl implements CryptInterface
{
    /**
     * Cryptography library name associated with this class
     *
     * @access private
     */
    public $libName = 'Openssl';

    /**
     * Constructor
     *
     * @throws \Exception extension unloaded/no supported cipher
     * @access public
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception("Openssl->__construct(): OpenSSL PHP extension is not loaded.");
        }
        if (Config::read("cipher{$this->libName}") === null) {
            $cipherPrefs = Config::read("cipherPrefs{$this->libName}");
            if (empty($cipherPrefs)) {  // If config value was empty
                $cipherPrefs = ['aes-256-gcm', 'aes-256-ccm', 'aes-256-cbc'];  // Default to some 256-bit encryption methods
            }
            $cipherPrefs = array_fill_keys($cipherPrefs, false);
            foreach (openssl_get_cipher_methods() as $cipher) {
                $cipherPrefs[$cipher] = true;
            }
            foreach ($cipherPrefs as $cipher => $supported) {
                if ($supported) {
                    Config::write("cipher{$this->libName}", $cipher);
                    break;
                }
            }
            if (Config::read("cipher{$this->libName}") === null) {
                throw new \Exception("Openssl->__construct(): No supported [preferred] ciphers found.");
            }
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
        return random_bytes(32);
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
        if (mb_strlen($key, '8bit') !== 32) {
            throw new \Exception("Openssl->__validateKey(): 256-bit key required.");
        }
        return true;
    }

    /**
     * Encrypts (and base64 encodes) using OpenSSL encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @param string $cipher (optional)
     * @return string $ciphertext
     * @access public
     */
    public function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }

        $cipher = Config::read("cipher{$this->libName}");
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));  // Initialization vector
        $tag = '';  // Tag, filled by openssl_encrypt
        $ciphertext = version_compare(PHP_VERSION, '7.1.0') >= 0 ? openssl_encrypt($plaintext, $cipher, Config::read("key{$this->libName}"), OPENSSL_RAW_DATA, $iv, $tag) : openssl_encrypt($plaintext, $cipher, Config::read("key{$this->libName}"), OPENSSL_RAW_DATA, $iv);
        $ciphertext = $iv . $tag . $ciphertext;

        if (stripos($cipher, '-gcm') === false) {  // If not a GCM-based encryption method
            $ciphertext = hash_hmac('sha256', $ciphertext, Config::read("key{$this->libName}") . $ciphertext);  // Include MAC for authenticated encyption
        }

        if ($base64) {  // Optionally, base 64 encode encrypted data
            return base64_encode($ciphertext);
        }

        return $ciphertext;
    }

    /**
     * Decrypts (and optionally converts from base64) using OpenSSL decryption
     *
     * @param string $ciphertext
     * @param bool $base64 [true]
     * @param string $cipher (optional)
     * @return string $plaintext
     * @throws \Exception extension unable to decode/authenticate
     * @access public
     */
    public function decrypt($ciphertext, $base64 = true)
    {
        if (empty($ciphertext)) {
            return $ciphertext;
        }

        if (!empty($base64)) {
            $ciphertext = base64_decode($ciphertext);
            if ($ciphertext === false) {
                throw new Exception('Openssl->decrypt(): Could not base64 decode ciphertext.');
            }
        }

        $cipher = Config::read("cipher{$this->libName}");
        $ivLen = openssl_cipher_iv_length($cipher);
        $tagLen = version_compare(PHP_VERSION, '7.1.0') >= 0 ? 16 : 0;
        $hmacLen = stripos($cipher, '-gcm') === false ? 32 : 0;

        if ($hmacLen != 0 && !hash_equals(mb_substr($ciphertext, 0, $hmacLen), hash_hmac('sha256', mb_substr($ciphertext, $hmacLen, null, '8bit'), $key, true))) {  // PHP 5.6+ timing attack safe comparison
            throw new \Exception("Openssl->decrypt(): MAC is invalid, unable to authenticate.");
        }

        if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
            return rtrim(openssl_decrypt(
                mb_substr($ciphertext, $hmacLen + $ivLen + $tagLen, null, '8bit'),
                $cipher,
                Config::read("key{$this->libName}"),
                OPENSSL_RAW_DATA,
                mb_substr($ciphertext, $hmacLen, $ivLen, '8bit'),           // IV
                mb_substr($ciphertext, $hmacLen + $ivLen, $tagLen, '8bit')  // Tag
            ), "\0");
        } else {
            return rtrim(openssl_decrypt(
                mb_substr($ciphertext, $hmacLen + $ivLen + $tagLen, null, '8bit'),
                $cipher,
                Config::read("key{$this->libName}"),
                OPENSSL_RAW_DATA,
                mb_substr($ciphertext, $hmacLen, $ivLen, '8bit')            // IV
            ), "\0");
        }
    }
}
