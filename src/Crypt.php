<?php
namespace BenjaminStout\Crypt;

use BenjaminStout\Crypt\Config;
use BenjaminStout\Crypt\lib\Sodium;

include('autoload.php');

/**
 * Cryptography class to facilitate all cryptographic measures
 *
 */
class Crypt
{
    /**
     *
     *
     * @access protected
     * @static
     */
    protected static $key = NULL;

    /**
     * Holds the current cryptography library class object
     *
     * @access private
     * @static
     */
    private static $lib = NULL;

    /**
     * Constructor
     *
     * @var string $lib
     * @var string $key
     * @throws Exception (unable to instantiate cryptography library)
     * @access public
     */
    public function __construct($lib = 'Sodium', $key = NULL)
    {
        $class = "BenjaminStout\Crypt\lib\\$lib";
        self::$lib = new $class();
        if (!self::$lib instanceof $class) {
            throw new \Exception("Crypt->__construct(): Unable to load the cryptography library: {$lib}");
        }
        self::$lib::init_key($key);
        self::memzero($key);
    }

    /**
     * Attempts to zero a variable's physical memory as much as possible
     *
     * @param &$var
     * @access public
     * @static
     */
    public static function memzero(&$var) {
        if (is_string($var)) {
            $len = strlen($var);
            for( $i = -1; ++$i < $len;) {
                $var[$i] = "\0";
            }
        } elseif (is_array($var)) {
            array_map(function() { return NULL; }, $var);
        }
        $var = NULL;
    }

    /**
     * Encrypts a string and returns the cipher
     * (optional) You may choose to base64 encode the returned cipher
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public static function encrypt($plaintext, $base64 = true)
    {
        return self::$lib::encrypt($plaintext, $base64);
    }

    /**
     * Decrypts a cipher and returns the plaintext
     * (optional) You may choose to base64 decode the passed cipher
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     * @static
     */
    public static function decrypt($cipher, $base64 = true)
    {
        return self::$lib::decrypt($cipher, $base64, $redactCC);
    }
}