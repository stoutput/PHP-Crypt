<?php

namespace BenjaminStout\Crypt\lib;

interface CryptInterface
{
    /**
     * Generates and returns a randomly-generated encryption key using a library-specific method
     *
     * @return string $key
     * @access public
     */
    public function generateKey();

    /**
     * Validates encryption key against a set of library-specific rules
     *
     * @param string $key
     * @return bool valid, else
     * @throws \Exception invalid
     * @access public
     */
    public function validateKey($key = null);

    /**
     * Encrypts (and base64 encodes) using Sodium encryption
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public function encrypt($plaintext, $base64 = true);

    /**
     * Decrypts (and optionally converts from base64) using sodium decryption
     *
     * @param string $cipher
     * @param bool $base64 [true]
     * @return string $plaintext
     * @access public
     * @static
     */
    public function decrypt($cipher, $base64 = true);
}
