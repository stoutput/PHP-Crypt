<?php
/**
 * Custom cryptography library to facilitate all cryptographic measures
 *
 */

namespace Crypt;

use Crypt\Mcrypt;
use Crypt\OpenSsl;
use Crypt\Sodium;

class Crypt
{
    protected static $key = NULL;

    private static $engine = NULL;

    /**
     * Constructor
     */
    public function __construct($key = null, $engine = 'Sodium')
    {
        if ($key !== null) {
            self::set_key((string)$key);
            self::memzero($key);
        }
        if (class_exists((string)$engine)) {
            self::$engine = $engine;
        }
    }

    /**
     * Attempts to zero a variable's physical memory as much as possible
     *
     * @param &$var
     */
    public static function memzero(&$var) {
        if (is_string($var)) {
            $len = strlen($var) - 1;
            for( $i = -1; $i < $len;)
                $var[++$i] = "\0";
            }
        } elseif (is_array($var)) {
            array_map(function() { return NULL; }, $var);
        }
        $var = NULL;
    }

    /**
     * Encrypts (and optionally base64 encodes) a string and returns the cipher
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     */
    public static function encrypt($plaintext, $base64 = true)
    {
        return self::$engine::encrypt($plaintext, $base64);
    }

    public static function decrypt($cipher, $base64 = true)
    {
        return self::$engine::decrypt($cipher, $base64, $redactCC);
    }
}