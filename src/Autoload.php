<?php
namespace BenjaminStout\Crypt;

spl_autoload_extensions(".php");

spl_autoload_register(
    function ($class) {
        if (is_string($class) && !class_exists($class)) {
            $fpath = str_replace('\\', DS, str_replace(__NAMESPACE__, __DIR__, $class)) . '.php';
            if (file_exists($fpath)) {
                include $fpath;
            }
        }
    }
);
