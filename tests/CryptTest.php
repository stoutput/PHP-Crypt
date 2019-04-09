<?php

namespace BenjaminStout\Crypt\Tests;

use BenjaminStout\Crypt\Config;
use BenjaminStout\Crypt\Tests\CryptTestCase;

/**
 * Class CryptTest
 *
 * @package BenjaminStout\Crypt\Tests
 * @author  Benjamin Stout
 */
class CryptTest extends CryptTestCase
{
    /**
     * @access public
     */
    public function setUp($lib = 'Sodium')
    {
        parent::setUp($lib);
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testInitKey()
    {
        // Test – key is generated, saved to file, and set properly in Config
        $testKeyFile = Config::read('keyPath') . DS . 'sodium.key';
        $this->assertTrue($this->Crypt->initKey('Sodium'));
        $this->assertFileExists($testKeyFile);
        $this->assertEquals($testKeyFile, Config::read('keyPathSodium'));
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, mb_strlen(Config::read('keySodium'), '8bit'));
    }

    public function testInitKeyCustom()
    {
        // Test – passed key is saved to file and set properly in Config
        $testKey = '01234567890123456789012345678901'; // 32 bytes
        $testKeyFile = Config::read('keyPath') . DS . 'sodium.custom.key';
        $this->assertTrue($this->Crypt->initKey('Sodium', $testKey));
        $this->assertFileExists($testKeyFile);
        $this->assertEquals($testKeyFile, Config::read('keyPathSodium'));
        $this->assertEquals($testKey, Config::read('keySodium'));
    }

    public function testInitKeyException()
    {
        // Test – invalid passed key throws Exception
        $testKey = '0123456789012345678901234567890'; // 31 bytes
        $this->expectException(\Exception::class);
        $this->Crypt->initKey('Sodium', $testKey);
    }

    public function testMemzero()
    {
        $data = [  // Test all variable types except resources
            'string',
            999,
            ['test', 'array', 1, true, null, 1.11, (object)'string'],
            null,
            (object)'string',
            true,
            9.99,
        ];

        $Crypt = $this->Crypt;  // PHP 5.6 compatability
        foreach ($data as $var) {
            $Crypt::memzero($var);
            $this->assertTrue($var === null);
        }
    }
}
