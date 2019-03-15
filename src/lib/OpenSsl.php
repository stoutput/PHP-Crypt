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
    private $libName = 'Openssl';

    /**
     * Current cipher method (initialized in constructor)
     *
     * @access private
     */
    private $cipher = null;

    /**
     * A list of OpenSSL cipher methods in descending order of preference
     * Used by constructor to choose best available cipher
     *
     * @access private
     */
    private $cipherPrefs = [
        'aes-256-gcm',          // Fast, secure, and supports authenticated encryption
        'aes-256-ccm',          // Slower than GCM, but supports authenticated encryption
        'aes-256-cbc',          // Secure, but does not support authenticated encryption, requiring manual computation
    ];

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
        $cipherPrefs = array_fill_keys($this->cipherPrefs, false);
        foreach (openssl_get_cipher_methods() as $cipher) {
            $cipherPrefs[$cipher] = true;
        }
        foreach ($cipherPrefs as $cipher => $supported) {
            if ($supported) {
                $this->cipher = $cipher;
                break;
            }
        }
        if ($this->cipher === null) {
            throw new \Exception("Openssl->__construct(): No supported [preferred] ciphers found.");
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

        // Initialization vector + encrypted data
        $ciphertext = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher)) . openssl_encrypt($plaintext, $this->cipher, Config::read('key'), OPENSSL_RAW_DATA, $iv);

        if (stripos($this->cipher, '-gcm') === false) {  // If not a GCM-based encryption method
            $ciphertext = hash_hmac('sha256', $ciphertext, Config::read('key') . $ciphertext);  // Include MAC for authenticated encyption
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
        if (!empty($base64)) {
            $ciphertext = base64_decode($ciphertext);
            if ($ciphertext === false) {
                throw new Exception('Crypto::decrypt_openssl [ERROR]: Could not base64 decode ciphertext.');
            }
        }

        $ivLen= openssl_cipher_iv_length($this->cipher);
        $hmacLen = stripos($this->cipher, '-gcm') === false ? 32 : 0;

        if ($hmacLen != 0 && !hash_equals(mb_substr($ciphertext, 0, $hmacLen), hash_hmac('sha256', mb_substr($ciphertext, $hmacLen, null, '8bit'), $key, true))) {  // PHP 5.6+ timing attack safe comparison
            throw new \Exception("Openssl::decrypt(): MAC is invalid, unable to authenticate.");
        }

        return openssl_decrypt(
            mb_substr($ciphertext, $ivLen + $hmacLen, null, '8bit'),
            $this->cipher,
            $key,
            OPENSSL_RAW_DATA,
            mb_substr($ciphertext, $hmacLen, $ivLen, '8bit')
        );
    }
}
