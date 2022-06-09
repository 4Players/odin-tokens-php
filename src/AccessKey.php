<?php

namespace FourPlayers\Odin;

/**
 * Class to handle ODIN access keys.
 *
 * @package FourPlayers\Odin
 */
final class AccessKey
{
  /**
   * Stores the raw access key string.
   *
   * @var string
   */
  private $seed = "";

  /**
   * Stores the raw public key string of the current access key.
   *
   * @var string
   */
  private $pk = "";

  /**
   * Stores the raw secret key string  of the current access key.
   *
   * @var string
   */
  private $sk = "";

  /**
   * The AccessKey constructor.
   */
  public function __construct($string = null)
  {
    $this->seed = $string ? base64_decode($string) : $this->generate();

    \ParagonIE_Sodium_Core_Ed25519::seed_keypair($this->pk, $this->sk, substr($this->seed, 1));
  }

  /**
   * Returns the access key string.
   *
   * @return string
   */
  public function __toString()
  {
    return base64_encode($this->seed);
  }

  /**
   * Returns the key ID of the current access key.
   *
   * @return string
   */
  public function getKeyId()
  {
    $hash = hash("sha512", $this->pk, true);
    $data = array(0x01);

    for ($i = 0, $x = 0; $i < 8; $i++) {
      for ($j = 0; $j < 8; $j++, $x++) {
        $data[$j+1] ^= ord($hash[$x]);
      }
    }

    return base64_encode(implode("", array_map("chr", $data)));
  }

  /**
   * Returns the public key of the current access key.
   *
   * @return string
   */
  public function getPublicKey()
  {
    return base64_encode($this->pk);
  }

  /**
   * Returns the secret key of the current access key.
   *
   * @return string
   */
  public function getSecretKey()
  {
    return base64_encode($this->sk);
  }

  /**
   * Generates a new access key.
   *
   * @return string
   */
  private function generate()
  {
    $bytes = random_bytes(31);
    $check = $this->crc8($bytes);

    return chr(0x01) . $bytes . chr($check);
  }

  /**
   * Calculates the crc8 polynomial of a string.
   *
   * @param  string $string
   * @return int
   */
  private function crc8($string) {
    $crc = 0xff;

    for ($i = 0; $i < strlen($string); $i++) {
      $crc ^= ord($string[$i]);

      for ($j = 0; $j < 8; $j++) {
        if (($crc & 0x80) !== 0) {
          $crc = ($crc << 1) ^ 0x31;
        } else {
          $crc <<= 1;
        }
      }

      $crc = 0xff & $crc;
    }

    return $crc;
  }
}
