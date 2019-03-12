<?php

namespace BenjaminStout\Crypt;

class Config
{
    private static $config = [
        'key' => null,                                  // Currently-set encryption key
        'keyPath' => __DIR__ . '..' . DS . 'keys',      // Path to key store (default is ../keys)
        'keyPathSodium' => null,                        // Unique path to Sodium key (used if valid)
        'keyPathOpenssl' => null,                       // Unique path to OpenSSL key (used if valid)
        'keyPathMcrypt' => null,                        // Unique path to Mcrypt key (used if valid)
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
     * Sets the value in static::$config at index $key to $val
     *
     * @var string key
     * @var mixed $val
     * @return bool success
     * @access public
     */
    public static function write($key, $val = null)
    {
        if (is_string($key) || is_integer($key)) {
            static::$config[$key] = $val;
            return true;
        } elseif (is_array($key)) {
            foreach ($key as $key => $val) {
                static::$config[$key] = $val;
            }
            return true;
        }
        return false;
    }
}
