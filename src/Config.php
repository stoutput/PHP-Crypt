<?php

namespace BenjaminStout\Crypt;

class Config
{
    private static $config = [
        'keyPath' => __DIR__ . DS . '..' . DS . 'keys', // Absolute path to key store, no trailing slash (default is ../keys)
        'keySodium' => null,                            // Holds the currently-set Sodium encryption key
        'keyOpenssl' => null,                           // Holds the currently-set OpenSSL encryption key
        'keyMcrypt' => null,                            // Holds the currently-set Mcrypt encryption key
        'keyPathSodium' => null,                        // Unique path to Sodium key (used if valid)
        'keyPathOpenssl' => null,                       // Unique path to OpenSSL key (used if valid)
        'keyPathMcrypt' => null,                        // Unique path to Mcrypt key (used if valid)
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
