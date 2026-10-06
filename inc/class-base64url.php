<?php
/**
 * Base64url encoding without padding, as used by WebAuthn.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

/**
 * Base64url helpers.
 */
class Base64url {

	/**
	 * Encode binary data.
	 *
	 * @param string $data Binary data.
	 * @return string
	 */
	public static function encode( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Decode a base64url string.
	 *
	 * @param string $data Base64url string, with or without padding.
	 * @return string|null Binary data, or null if the input is not valid base64url.
	 */
	public static function decode( string $data ): ?string {
		if ( ! preg_match( '/^[A-Za-z0-9_-]*={0,2}\z/', $data ) ) {
			return null;
		}

		$decoded = base64_decode( strtr( rtrim( $data, '=' ), '-_', '+/' ), true );
		return $decoded === false ? null : $decoded;
	}
}
