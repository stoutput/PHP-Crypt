<?php

namespace BenjaminStout\Crypt\lib;

class OpenSsl extends Crypt
{

    private static $method = 'AES-256-CBC';

    /**
     * Constructor
     */
    public function __construct()
    {
    }

    public static function initKey($key)
    {
        Config::write('key', $key);
    }

    /**
     * Encrypts (and base64 encodes) using OpenSSL encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @param string $method (optional)
     * @return string $cipher
     * @access public
     * @static
     */
    public static function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }

        if ($method === null) {
            $method = self::$method;
        }

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
        $cipher = $iv . openssl_encrypt($plaintext, $method, self::key(), OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(openssl_cipher_iv_length($method)));
        if ($base64) {
            return base64_encode($cipher);
        }
        return $cipher;
    }

    /**
     * Decrypts (and optionally converts from base64) using OpenSSL decryption
     *
     * @param string $cipher
     * @param bool $base64 [true]
     * @param string $method (optional)
     * @return string $plaintext
     * @access public
     * @static
     */
    public static function decrypt($cipher, $base64 = true)
    {
        if ($method === null) {
            $method = self::$method;
        }

        if (!empty($base64)) {
            $cipher = base64_decode($cipher);
            if ($cipher === false) {
                throw new Exception('Crypto::decrypt_openssl [ERROR]: Could not base64 decode cipher.');
            }
        }

        $key = self::key();
        if (mb_strlen($key, '8bit') !== 32) {
            throw new Exception("Needs a 256-bit key!");
        }
        $ivsize = openssl_cipher_iv_length($method);
        $iv = mb_substr($message, 0, $ivsize, '8bit');
        $ciphertext = mb_substr($message, $ivsize, null, '8bit');
        
        return openssl_decrypt(
            $ciphertext,
            self::METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
}
