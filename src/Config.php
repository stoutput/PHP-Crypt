<?php

namespace BenjaminStout\Crypt;

class Config
{
    private static $config = [
        'key' => null,                              // Currently-set encryption key
        'keyPath' => __DIR__ . '..' . DS . 'keys',  // Path to key store (default is ../keys)
        'keySodium' => null,                        // Unique path to Sodium key (used if valid)
        'keyOpenssl' => null,                       // Unique path to OpenSSL key (used if valid)
        'keyMcrypt' => null,                        // Unique path to Mcrypt key (used if valid)
    ];

    /**
     * Merges passed array with config array, overwriting duplicates
     *
     * @var array $arr
     * @return bool success
     * @access public
     */
    public static function merge($arr)
    {
        self::$config = array_merge(self::$config, $arr);
        return true;
    }

    /**
     * Returns the value from self::$config at index $key if set
     * Otherwise, returns null
     *
     * @var string key
     * @return mixed value, else null
     * @access public
     */
    public static function read($key)
    {
        return isset(self::$config[$key]) ? self::$config[$key] : null;
    }

    /**
     * Sets the value in self::$config at index $key to $val
     *
     * @var string key
     * @var mixed $val
     * @return bool success
     * @access public
     */
    public static function write($key, $val)
    {
        if (is_string($key) || is_integer($key)) {
            self::$config[$key] = $val;
            return true;
        }
        return false;
    }
}