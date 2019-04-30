<?php

namespace BenjaminStout\PHPCrypt;

class Config
{
    private static $config = [
        'keyPath' => DS . 'etc' . DS . 'keystore',      // Absolute path to key store, no trailing slash (default is ../keys)
        'keySodium' => null,                            // Holds the currently-set Sodium encryption key
        'keyOpenssl' => null,                           // Holds the currently-set OpenSSL encryption key
        'keyMcrypt' => null,                            // Holds the currently-set Mcrypt encryption key
        'keyPathSodium' => null,                        // Unique path to Sodium key (used if valid)
        'keyPathOpenssl' => null,                       // Unique path to OpenSSL key (used if valid)
        'keyPathMcrypt' => null,                        // Unique path to Mcrypt key (used if valid)
        'cipherMcrypt' => MCRYPT_3DES,                  // Mcrypt cipher method
        'cipherOpenssl' => null,                        // OpenSSL cipher method (initialized in constructor)
        'modeMcrypt' => MCRYPT_MODE_ECB,                // Mcrypt encryption mode
        'cipherPrefsOpenssl' => [                       // OpenSSL cipher methods in descending order of preference, used by constructor to choose best available cipher
            'aes-256-gcm',                              // Fast, secure, and supports authenticated encryption (unsupported on PHP <= 7.0)
            'aes-256-ccm',                              // Slower than GCM, but supports authenticated encryption (unsupported on PHP <= 7.0)
            'aes-256-cbc',                              // Secure, but does not support authenticated encryption, requiring manual computation
        ],
    ];

    private static $default = [];


    public static function reset()
    {
        if (!empty(static::$default)) {
            static::$config = static::$default;
        }
    }

    public static function backup()
    {
        if (empty(static::$default)) {
            static::$default = static::$config;
        }
    }

    /**
     * Merges passed array with config array, overwriting duplicates
     *
     * @var array $arr
     * @return bool success
     * @access public
     */
    public static function merge($arr)
    {
        static::backup();
        static::$config = array_merge(static::$config, $arr);
        return true;
    }

    /**
     * Returns the value from static::$config at index $key if set
     * Otherwise, returns null
     *
     * @var string key
     * @return mixed value, else null
     * @access public
     */
    public static function read($key)
    {
        return isset(static::$config[$key]) ? static::$config[$key] : null;
    }

    /**
     * Sets the value on static::$config[$key] to $val
     * Also supports array of key/value pairs as first arg
     *
     * @var string key
     * @var mixed $val
     * @return bool success
     * @access public
     */
    public static function write($key, $val = null)
    {
        if (is_array($key)) {
            return static::merge($key);
        }
        static::backup();
        static::$config[$key] = $val;
        return true;
    }
}
