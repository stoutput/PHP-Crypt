<?php

namespace BenjaminStout\Crypt\lib;

class Mcrypt implements CryptInterface
{
    /**
     * Cryptography library name associated with this class
     *
     * @access private
     */
    private $libName = 'Mcrypt';

    /**
     * Constructor
     *
     * @throws \Exception extension unloaded
     * @access public
     */
    public function __construct()
    {
        if (!extension_loaded('mcrypt')) {
            throw new \Exception("Mcrypt->__construct(): Mcrypt PHP extension is not loaded.");
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
        $keyLen = mb_strlen($key, '8bit');
        if ($keyLen != 32 || $keyLen != 24 || $keyLen != 16) {
            throw new \Exception('Sodium->validateKey(): Invalid key length, must be 16, 24, or 32 bytes long.');
        }
        return true;
    }

    /**
     * Encrypts (and base64 encodes) using Mcrypt encryption
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
        $secretKey = self::mcrypt_key();
        $iv_size = mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $cipher = mcrypt_encrypt(MCRYPT_3DES, $secretKey, $plaintext, MCRYPT_MODE_ECB, $iv);
        if ($base64) {
            return base64_encode($cipher);
        }
        return $cipher;
    }

    /**
     * Decrypts (and optionally converts from base64) using Mcrypt decryption
     *
     * @param string $cipher
     * @param bool $base64 [true]
     * @return string $plaintext
     * @access public
     */
    public function decrypt($cipher, $base64 = true)
    {
        $secretKey = self::mcrypt_key();
        $iv_size = mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        if ($base64) {
            $cipher = base64_decode($cipher);
        }
        $plaintext = mcrypt_decrypt(MCRYPT_3DES, $secretKey, $cipher, MCRYPT_MODE_ECB, $iv);
        if (is_numeric($cipher) && !is_numeric($plaintext)) {
            $plaintext = $cipher;
        }
        return $plaintext;
    }
}
