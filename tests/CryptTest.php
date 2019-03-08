<?php

namespace BenjaminStout\Crypt\Tests

use BenjaminStout\Crypt

/**
 * Class RSATest
 *
 * @package BenjaminStout\Crypt\Tests
 * @author  Benjamin Stout
 */
class CryptTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var Crypt
     */
    public $Crypt;

    /**
     *
     */
    public function setUp() {
        $this->Crypt = new Crypt();
    }
}