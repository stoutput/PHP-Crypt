<?php

namespace BenjaminStout\Crypt\lib;

use BenjaminStout\Crypt\Config;

class Sodium
{
    /**
     * Constructor
     */
    public function __construct()
    {
        /*if (sodium_init() < 0) {
            throw new Exception("Crypto::__construct() Error: Sodium encryption library unavailable.");
        }*/
    }

    public static function initKey($key)
    {
        Config::write('key', $key);
    }

    /**
     * Encrypts (and base64 encodes) using Sodium encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public static function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }

        $cipher = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) . crypto_secretbox($plaintext, $nonce, self::key());

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
     * @access public
     * @static
     */
    public static function decrypt($cipher, $base64 = true)
    {
        if (!empty($base64)) {
            $cipher = base64_decode($cipher);
            if ($cipher === false) {
                throw new Exception('Crypto::decrypt_sodium [ERROR]: Could not base64 decode cipher.');
            }
            if (mb_strlen($cipher, '8bit') < (CRYPTO_SECRETBOX_NONCEBYTES + CRYPTO_SECRETBOX_MACBYTES)) {
                throw new Exception('Crypto::decrypt_sodium [ERROR]: Cipher was truncated.');
            }
        }

        $nonce = mb_substr($cipher, 0, CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($cipher, CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plaintext = crypto_secretbox_open($ciphertext, $nonce, self::key());
        if ($plaintext === false) {
             throw new Exception('Crypto::decrypt_sodium [ERROR]: Cipher has been compromised – decryption failed.');
        }

        sodium_memzero($ciphertext);
        sodium_memzero($cipher);

        return $plaintext;
    }
}