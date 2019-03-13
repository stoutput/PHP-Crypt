<?php

namespace BenjaminStout\Crypt\Tests;

use BenjaminStout\Crypt\Crypt;
use BenjaminStout\Crypt\Config;

include __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Autoload.php';

/**
 * Class CryptTest
 *
 * @package BenjaminStout\Crypt\Tests
 * @author  Benjamin Stout
 */
class CryptTestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Crypt
     * @access public
     */
    public $Crypt;

    /**
     * @access public
     */
    public function setUp($lib = 'Sodium')
    {
        Config::reset();
        Config::write('keyPath', Config::read('keyPath') . DS . 'test');
        $this->Crypt = new Crypt($lib);
    }

    public function tearDown()
    {
        array_map('unlink', glob(Config::read('keyPath') . DS . '/*'));
        rmdir(Config::read('keyPath'));
    }

    /**
     * Test helper function to test if string is valid base 64 encoded
     *
     * @access public
     */
    public function isBase64($str)
    {
        return $str === base64_encode(base64_decode($str, true));
    }
}
