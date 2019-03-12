<?php

namespace BenjaminStout\Crypt\lib;

class Openssl implements CryptInterface
{

    private static $method = null;

    private $methodPrefs = [
        'aes-256-gcm',
        'aes-256-cbc'
    ];

    /**
     * Constructor
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception("Openssl->__construct(): OpenSSL PHP extension is not loaded.");
        }
        $methodPrefs = array_fill_keys($this->$methodPrefs, false);
        foreach (openssl_get_cipher_methods() as $cipher) {
            $methodPrefs[$cipher] = true;
        }
        foreach ($methodPrefs as $method => $supported) {
            if ($supported) {
                static::$method = $method;
                break;
            }
        }
        if (static::$method === null) {
            throw new \Exception("Openssl->__construct(): No supported [preferred] ciphers found.")
        }
    }

    /**
     * Fetches or generates, then saves, the current encryption key
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     */
    public function initKey($key)
    {
        if (mb_strlen($key, '8bit') !== 32) {
            throw new Exception("Openssl->__decrypt(): Needs a 256-bit key!");
        }
        Config::write('key', $key);
    }

    /**
     * Encrypts (and base64 encodes) using OpenSSL encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @param string $method (optional)
     * @return string $ciphertext
     * @access public
     */
    public function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }

        // Initialization vector + encrypted data
        $ciphertext = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method)) . openssl_encrypt($plaintext, $method, Config::read('key'), OPENSSL_RAW_DATA, $iv);

        if (stripos(static::$method, '-gcm') === false) {  // If not a GCM-based encryption method
            $ciphertext = hash_hmac('sha256', $ciphertext, Config::read('key') . $ciphertext;  // Include MAC for authenticated encyption
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
     * @param string $method (optional)
     * @return string $plaintext
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

        $ivLen= openssl_cipher_iv_length($method);
        $hmacLen = stripos(static::$method, '-gcm') === false ? 32 : 0;

        if ($hmacLen != 0 && !hash_equals(mb_substr($ciphertext, 0, $hmacLen), hash_hmac('sha256', mb_substr($ciphertext, $hmacLen, null, '8bit'), $key, true))) {  // PHP 5.6+ timing attack safe comparison
            throw new \Exception("Openssl::decrypt(): MAC is invalid, unable to authenticate.")
        }

        return openssl_decrypt(
            mb_substr($ciphertext, $ivLen + $hmacLen, null, '8bit'),
            static::$method,
            $key,
            OPENSSL_RAW_DATA,
            mb_substr($ciphertext, $hmacLen, $ivLen, '8bit')
        );
    }
}
