<?php
namespace BenjaminStout\Crypt;

use BenjaminStout\Crypt\lib\Mcrypt;
use BenjaminStout\Crypt\lib\OpenSsl;
use BenjaminStout\Crypt\lib\Sodium;

/**
 * Cryptography class to facilitate all cryptographic measures
 *
 */
class Crypt
{
    protected static $key = NULL;

    private static $lib = NULL;

    /**
     * Constructor
     */
    public function __construct($key = null, $lib = 'Sodium')
    {
        if ($key !== null) {
            self::set_key((string)$key);
            self::memzero($key);
        }
        if (class_exists("\Crypt\{$lib}")) {
            require_once(dirname(__FILE__) . "/{$lib}.php");
            self::$lib = new $lib();
        }
    }

    /**
     * Attempts to zero a variable's physical memory as much as possible
     *
     * @param &$var
     */
    public static function memzero(&$var) {
        if (is_string($var)) {
            $len = strlen($var);
            for( $i = -1; ++$i < $len;)
                $var[$i] = "\0";
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
        return self::$lib::encrypt($plaintext, $base64);
    }

    public static function decrypt($cipher, $base64 = true)
    {
        return self::$lib::decrypt($cipher, $base64, $redactCC);
    }
}