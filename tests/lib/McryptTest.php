<?php

namespace BenjaminStout\Crypt\Tests\lib;

use BenjaminStout\Crypt\Config;
use BenjaminStout\Crypt\Tests\CryptTestCase;

error_reporting(E_ALL ^ E_DEPRECATED);  // Disable Mcrypt deprecation error reporting

/**
 * Class McryptTest
 *
 * @package BenjaminStout\Crypt\Tests\lib
 * @author  Benjamin Stout
 */
class McryptTest extends CryptTestCase
{
    /**
     * @access public
     */
    public function setUp($lib = 'Mcrypt')
    {
        parent::setUp($lib);
    }

    /**
     * @access public
     */
    public function tearDown()
    {
        parent::tearDown();
    }

    public function testEncryptDecrypt()
    {
        $plaintext = " plain old string ";

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, false);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertFalse($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, false);
        $expected = $plaintext . str_repeat("\0", 24 - mb_strlen($plaintext, '8bit'));  // expect mcrypt to null-pad to 24 bytes
        $this->assertSame($expected, $decrypted);
    }

    public function testEncryptDecryptBase64()
    {
        $plaintext = " plain old string ";  // 24 bytes

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, true);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertTrue($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, true);
        $expected = $plaintext . str_repeat("\0", 24 - mb_strlen($plaintext, '8bit'));  // expect mcrypt to null-pad to 24 bytes
        $this->assertSame($expected, $decrypted);
    }

    public function testDecryptExceptions()
    {
        $plaintext = " plain old string ";  // 24 bytes

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, false);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertFalse($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, false);
        $expected = $plaintext . str_repeat("\0", 24 - mb_strlen($plaintext, '8bit'));  // expect mcrypt to null-pad to 24 bytes
        $this->assertSame($expected, $decrypted);
    }
}
