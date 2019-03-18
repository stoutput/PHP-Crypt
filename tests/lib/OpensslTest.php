<?php

namespace BenjaminStout\Crypt\Tests\lib;

use BenjaminStout\Crypt\Config;
use BenjaminStout\Crypt\Tests\CryptTestCase;

/**
 * Class OpensslTest
 *
 * @package BenjaminStout\Crypt\Tests\lib
 * @author  Benjamin Stout
 */
class OpensslTest extends CryptTestCase
{
    /**
     * @access public
     */
    public function setUp($lib = 'Openssl')
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
        $plaintext = ' plain old string ';

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, false);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertFalse($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, false);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptDecryptBase64()
    {
        $plaintext = ' plain old string ';

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, true);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertTrue($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, true);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptExceptions()
    {
        $plaintext = ' plain old string ';

        // Encrypt
        $ciphertext = $this->Crypt->encrypt($plaintext, false);
        $this->assertTrue($ciphertext != $plaintext);
        $this->assertFalse($this->isBase64($ciphertext));

        // Decrypt
        $decrypted = $this->Crypt->decrypt($ciphertext, false);
        $this->assertSame($plaintext, $decrypted);
    }
}
