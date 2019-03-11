<?php
namespace BenjaminStout\Crypt;

spl_autoload_extensions(".php");

spl_autoload_register(function (String $class) {
    if (!class_exists($class)) {
        $fpath = str_replace('\\', DIRECTORY_SEPARATOR, str_replace(__NAMESPACE__, __DIR__, $class)) . '.php';
        if (file_exists($fpath)) {
            require($fpath);
        }
    }
});