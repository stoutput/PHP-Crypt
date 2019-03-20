<?php

namespace BenjaminStout\Crypt\lib;

use BenjaminStout\Crypt\Config;

class Mcrypt implements CryptInterface
{
    /**
     * Cryptography library name associated with this class
     *
     * @access private
     */
    public $libName = 'Mcrypt';

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
        return random_bytes(mcrypt_get_key_size(Config::read("cipher{$this->libName}"), Config::read("mode{$this->libName}")));
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
        if ($keyLen != 32 && $keyLen != 24 && $keyLen != 16) {
            throw new \Exception('Mcrypt->validateKey(): Invalid key length, must be 16, 24, or 32 bytes long.');
        }
        return true;
    }

    /**
     * Encrypts (and base64 encodes) using Mcrypt encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $ciphertext
     * @access public
     */
    public function encrypt($plaintext, $base64 = true)
    {
        if (empty($plaintext)) {
            return '';
        }
        $cipher = Config::read("cipher{$this->libName}");
        $mode = Config::read("mode{$this->libName}");
        $iv = $mode == MCRYPT_MODE_ECB ? '' : mcrypt_create_iv(mcrypt_get_iv_size($cipher, $mode), MCRYPT_RAND);  // IV not used for _ECB-based encryption mode
        $ciphertext = $iv . mcrypt_encrypt($cipher, Config::read("key{$this->libName}"), $plaintext, $mode, $iv);
        if ($base64) {
            return base64_encode($ciphertext);
        }
        return $ciphertext;
    }

    /**
     * Decrypts (and optionally converts from base64) using Mcrypt decryption
     *
     * @param string $ciphertext
     * @param bool $base64 [true]
     * @return string $plaintext
     * @access public
     */
    public function decrypt($ciphertext, $base64 = true)
    {
        if (empty($ciphertext)) {
            return $ciphertext;
        }

        if ($base64) {
            $ciphertext = base64_decode($ciphertext);
        }

        $cipher = Config::read("cipher{$this->libName}");
        $mode = Config::read("mode{$this->libName}");
        $ivLen = $mode == MCRYPT_MODE_ECB ? 0 : mcrypt_get_iv_size($cipher, $mode);  // IV not used for _ECB-based encryption mode

        $plaintext = mcrypt_decrypt(
            $cipher,
            Config::read("key{$this->libName}"),
            mb_substr($ciphertext, $ivLen, null, '8bit'),
            $mode,
            mb_substr($ciphertext, 0, $ivLen, '8bit')
        );

        return rtrim($plaintext, "\0"); // Return plaintext without null-padding
    }
}
