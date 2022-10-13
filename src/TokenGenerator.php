<?php

namespace FourPlayers\Odin;

/**
 * Class to handle ODIN tokens.
 *
 * @package FourPlayers\Odin
 */
final class TokenGenerator
{
  /**
   * Stores the access key used to generate tokens.
   *
   * @var \FourPlayers\Odin\AccessKey
   */
  private $accessKey;

  /**
   * The TokenGenerator constructor.
   *
   * @param  \FourPlayers\Odin\AccessKey|string $accessKey
   * @throws \Exception
   * @throws \SodiumException
   */
  public function __construct($accessKey)
  {
    if (!$accessKey instanceof AccessKey) {
      $accessKey = AccessKey::fromString($accessKey);
    }

    $this->accessKey = $accessKey;
  }

  /**
   * Creates a new token.
   *
   * @param  array|string $roomId
   * @param  string       $userId
   * @param  array        $options
   * @return string
   */
  public function createToken($roomId, $userId, $options = array())
  {
    $claims = array_filter(array(
      "rid" => $roomId,
      "uid" => strval($userId),
      "cid" => isset($options["customer"]) ?? strval($options["customer"]),
      "sub" => "connect",
      "aud" => isset($options["audience"]) ?? strval($options["audience"]),
      "exp" => time() + (isset($options["lifetime"]) ? intval($options["audience"]) : 300),
      "nbf" => time(),
    ), function($v) {
      return $v !== false;
    });

    $head = array("alg" => "EdDSA", "kid" => $this->accessKey->getKeyId());
    $mesg = $this->base64UrlEncode(json_encode($head)) . "." . $this->base64UrlEncode(json_encode($claims));
    $sign = \ParagonIE_Sodium_Core_Ed25519::sign($mesg, base64_decode($this->accessKey->getSecretKey()));

    return $mesg . "." . $this->base64UrlEncode($sign);
  }

  /**
   *  Encodes data with MIME base64 in an URL-safe variant.
   *
   * @param  string $data
   * @return string
   */
  private function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), "+/", "-_"), "=");
  }
}
