<?php
namespace BenjaminStout\PHPCrypt;

use BenjaminStout\PHPCrypt\Config;

/**
 * Cryptography class to facilitate cryptographic measures
 */
class Crypt
{
    /**
     * Holds the current cryptography library class object
     *
     * @access private
     * @static
     */
    private $lib = null;

    /**
     * Constructor
     *
     * @var string $lib
     * @var string $key
     * @throws Exception (unable to instantiate cryptography library)
     * @access public
     */
    public function __construct($lib = 'Sodium', $key = null)
    {
        require_once __DIR__ . DIRECTORY_SEPARATOR . 'Autoload.php';
        $lib = ucfirst(strtolower($lib));
        $class = __NAMESPACE__ . '\lib\\' . $lib;

        // Initialize cryptography library
        if (!$this->lib instanceof $class) {
            $this->lib = new $class();
            if (!$this->lib instanceof $class) {
                throw new \Exception("Crypt->__construct(): Unable to load the cryptography library: {$lib}");
            }
        }

        // Initialize key
        $this->initKey($lib, $key);
        if ($key !== null) {
            if (is_callable('sodium_memzero')) {  // Prefer sodium's memzero if available
                sodium_memzero($key);
            } else {
                self::memzero($key);
            }
        }
    }

    /**
     * Returns the library name of the currently set cryptography library
     *
     * @return string
     */
    public function getCryptLib()
    {
        if (empty($this->lib)) {
            return '';
        }
        return $this->lib->libName;
    }

    /**
     * Best-attempt method to zero a variable's physical memory as much as PHP allows
     *
     * @param &$var
     * @access public
     * @static
     */
    public static function memzero(&$var)
    {
        if (is_string($var)) {
            $len = strlen($var);
            for ($i = -1; ++$i < $len;) {
                $var[$i] = "\0";
            }
        } elseif (is_array($var)) {
            array_map(function () {
                return null;
            }, $var);
        }
        $var = null;
    }

    /**
     * Sets the key path and subsequently initializes or re-initializes
     * the encryption key for a specified library
     *
     * @param string $path
     * @return bool success
     * @access public
     */
    public function setPath($lib, $path)
    {
        if (!is_string($lib) || !is_string($path)) {
            return false;
        }

        $lib = strtolower($lib);
        $path = strtolower($lib);

        if ($lib == 'all') {
            if (!is_dir($path)) {
                return false;
            }
            Config::write('keyPath', $path);
            return true;
        }

        if (!is_file($path) || basename($path) !=  "$lib.key") {
            return false;
        }
        Config::write('keyPath' . ucfirst($lib), $path);
        return true;
    }

    /**
     * Fetches and returns the contents of a key file for a specified library
     *
     * @param string $lib
     * @return string or bool false on failure
     * @throws \Exception invalid keyPath directory
     * @access public
     */
    public function fetchKeyFromFile($lib)
    {
        if (!is_string($lib)) {
            return false;
        }

        // Option 1: test for existence and validity of keyPath<lib> file
        $path = Config::read("keyPath{$lib}");
        if (is_string($path)) {
            $pInfo = pathinfo($path);
            // Key path extension must be "key", filename must be lowercase, and file must exist to use
            if (!empty($pInfo['extension']) && strtolower($pInfo['extension']) == 'key' && !empty($pInfo['filename']) && $pInfo['filename'] == strtolower($pInfo['filename']) && file_exists($path)) {
                return file_get_contents($path);
            }
        }

        // Option 2: fall back to use keyPath folder
        $path = Config::read("keyPath");
        if (is_string($path)) {
            // Build path to key file
            $path = $path . (substr($path, -1) == DS ? '' : DS) . strtolower($lib) . '.key';
            if (is_file($path)) {
                return file_get_contents($path);
            }
        }

        return false;
    }

    public function saveKeyToFile($lib, $key, $custom = false)
    {
        $keyPath = Config::read('keyPath');
        if (!file_exists($keyPath)) {
            mkdir($keyPath, 0775, true);
        }
        if (!is_dir($keyPath)) {  // Path is either a file or a directory we can't create
            throw new \Exception("Crypt->fetchKeyFromFile(): Invalid keyPath directory: $path");
        }
        $keyPath .= substr($keyPath, -1) == DS ? strtolower($lib) : DS . strtolower($lib);
        $keyPath .= empty($custom) ? '.key' : '.custom.key';
        file_put_contents($keyPath, $key);
        return $keyPath;
    }

    /**
     * Fetches or generates, then saves, an encryption key for the passed library
     *
     * @param string $key
     * @return bool $success
     * @access public
     */
    public function initKey($lib, $key = null)
    {
        if ($key === null) {
            $key = $this->fetchKeyFromFile($lib);
            if (!empty($key)) {
                $this->lib->validateKey($key);
            } else {
                $key = $this->lib->generateKey();
                Config::write("keyPath{$lib}", $this->saveKeyToFile($lib, $key));
            }
        } else {
            $this->lib->validateKey($key);
            Config::write("keyPath{$lib}", $this->saveKeyToFile($lib, $key, true));
        }
        $success = Config::write("key{$lib}", $key);
        if (is_callable('sodium_memzero')) {  // Prefer sodium's memzero if available
            sodium_memzero($key);
        } else {
            self::memzero($key);
        }
        return $success;
    }

    /**
     * Encrypts a string and returns the cipher
     * (optional) You may choose to base64 encode the returned cipher
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $ciphertext
     * @access public
     */
    public function encrypt($plaintext, $base64 = true)
    {
        $ciphertext = $this->lib->encrypt($plaintext, $base64);
        if (is_callable('sodium_memzero')) {  // Prefer sodium's memzero if available
            sodium_memzero($plaintext);
        } else {
            self::memzero($plaintext);
        }
        return $ciphertext;
    }

    /**
     * Decrypts a cipher and returns the plaintext
     * (optional) You may choose to base64 decode the passed cipher
     *
     * @param string $plaintext
     * @param bool $base64 [true]
     * @return string $cipher
     * @access public
     */
    public function decrypt($cipher, $base64 = true)
    {
        return $this->lib->decrypt($cipher, $base64);
    }
}
