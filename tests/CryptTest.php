<?php

namespace BenjaminStout\Crypt;

/**
 * Class RSATest
 *
 * @package BenjaminStout\Crypt\Tests
 * @author  Benjamin Stout
 */
class CryptTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Crypt
     * @access public
     */
    public $Crypt;

    /**
     * @access public
     */
    public function setUp()
    {
        $this->Crypt = new Crypt();
    }

    public function testMemzero()
    {
        $data = [  // Test all variable types except resources
            'string',
            999,
            ['test', 'array', 1, true, null, 1.11, new Crypt()],
            null,
            new Crypt(),
            true,
            9.99,
        ];
        $Crypt = $this->Crypt;
        foreach ($data as $var) {
            $Crypt::memzero($var);
            $this->assertTrue($var === null);
        }
    }
}