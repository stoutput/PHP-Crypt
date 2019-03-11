<?php

namespace BenjaminStout\Crypt;

class Config
{
    private static $config = [
        'key' => NULL,
    ];

    public static function read($key)
    {
        return isset(self::$config[$key]) ? self::$config[$key] : NULL;
    }

    public static function write($key, $val)
    {
        self::$config[$key] = $val;
        return true;
    }
}