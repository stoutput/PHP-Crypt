<?php
namespace BenjaminStout\Crypt;

define('DS', DIRECTORY_SEPARATOR);

spl_autoload_extensions(".php");

spl_autoload_register(
    function (String $class) {
        if (!class_exists($class)) {
            $fpath = str_replace('\\', DS, str_replace(__NAMESPACE__, __DIR__, $class)) . '.php';
            if (file_exists($fpath)) {
                include $fpath;
            }
        }
    }
);