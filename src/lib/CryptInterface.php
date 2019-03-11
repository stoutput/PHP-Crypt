<?php

namespace BenjaminStout\Crypt\lib;

class CryptInterface {
    /**
     * Constructor
     */
    public function __construct();

    /**
     * Fetches or generates, then saves, the current encryption key
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public static function init_key($key);

    /**
     * Encrypts (and base64 encodes) using Sodium encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public static function encrypt($plaintext, $base64 = true);

    /**
     * Decrypts (and optionally converts from base64) using sodium decryption
     *
     * @param string $cipher
     * @param bool $base64 [true]
     * @return string $plaintext
     * @access public
     * @static
     */
    public static function decrypt($cipher, $base64 = true);
}