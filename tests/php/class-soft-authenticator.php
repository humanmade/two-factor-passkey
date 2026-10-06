<?php
/**
 * Software WebAuthn authenticator for tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Base64url;
use stdClass;

/**
 * Builds registration and login responses like a browser would send them.
 *
 * Challenge overrides are the base64url string as it appears in the options.
 * Binary overrides (credential_id, user_handle) are raw bytes.
 */
class Soft_Authenticator {

	/**
	 * Relying party ID hashed into authData.
	 *
	 * @var string
	 */
	public $rp_id;

	/**
	 * Origin reported in clientDataJSON.
	 *
	 * @var string
	 */
	public $origin;

	/**
	 * Current signature counter.
	 *
	 * @var int
	 */
	public $sign_count = 0;

	/**
	 * Raw credential ID.
	 *
	 * @var string
	 */
	public $credential_id;

	/**
	 * ES256 key pair.
	 *
	 * @var \OpenSSLAsymmetricKey
	 */
	private $key;

	/**
	 * Create an authenticator with a new key and credential ID.
	 *
	 * @param string $rp_id  RP ID.
	 * @param string $origin Origin.
	 */
	public function __construct( string $rp_id = 'example.org', string $origin = 'https://example.org' ) {
		$this->rp_id = $rp_id;
		$this->origin = $origin;
		$this->credential_id = random_bytes( random_int( 16, 32 ) );
		$this->key = openssl_pkey_new(
			[
				'curve_name' => 'prime256v1',
				'private_key_type' => OPENSSL_KEYTYPE_EC,
			]
		);
	}

	/**
	 * Get the credential ID as base64url.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return Base64url::encode( $this->credential_id );
	}

	/**
	 * Answer navigator.credentials.create().
	 *
	 * @param array $options   Creation options from Ceremony::get_creation_options().
	 * @param array $overrides Any of: origin, type, challenge, rp_id, flags, sign_count, cross_origin, credential_id, id.
	 * @return string PublicKeyCredential.toJSON() as a JSON string.
	 */
	public function create( array $options, array $overrides = [] ): string {
		$credential_id = $overrides['credential_id'] ?? $this->credential_id;
		$sign_count = $overrides['sign_count'] ?? $this->sign_count;

		$client_data = $this->client_data( 'webauthn.create', $options['challenge'], $overrides );

		$details = openssl_pkey_get_details( $this->key )['ec'];
		$cose_key = [
			1 => 2,
			3 => -7,
			-1 => 1,
			-2 => self::bytes( str_pad( $details['x'], 32, "\0", STR_PAD_LEFT ) ),
			-3 => self::bytes( str_pad( $details['y'], 32, "\0", STR_PAD_LEFT ) ),
		];

		$auth_data = hash( 'sha256', $overrides['rp_id'] ?? $this->rp_id, true )
			. chr( $overrides['flags'] ?? 0x45 )
			. pack( 'N', $sign_count )
			. str_repeat( "\0", 16 )
			. pack( 'n', strlen( $credential_id ) )
			. $credential_id
			. self::cbor( $cose_key );

		$attestation = self::cbor(
			[
				'fmt' => 'none',
				'attStmt' => new stdClass(),
				'authData' => self::bytes( $auth_data ),
			]
		);

		$id = $overrides['id'] ?? Base64url::encode( $credential_id );

		return wp_json_encode(
			[
				'id' => $id,
				'rawId' => $id,
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64url::encode( $client_data ),
					'attestationObject' => Base64url::encode( $attestation ),
					'transports' => [ 'internal' ],
				],
				'clientExtensionResults' => new stdClass(),
			]
		);
	}

	/**
	 * Answer navigator.credentials.get().
	 *
	 * @param array $options   Request options from Ceremony::get_request_options().
	 * @param array $overrides Any of: origin, type, challenge, rp_id, flags, sign_count, user_handle, credential_id, corrupt_signature, cross_origin.
	 * @return string PublicKeyCredential.toJSON() as a JSON string.
	 */
	public function get( array $options, array $overrides = [] ): string {
		$credential_id = $overrides['credential_id'] ?? $this->credential_id;

		if ( isset( $overrides['sign_count'] ) ) {
			$this->sign_count = $overrides['sign_count'];
		} else {
			++$this->sign_count;
		}

		$client_data = $this->client_data( 'webauthn.get', $options['challenge'], $overrides );

		$auth_data = hash( 'sha256', $overrides['rp_id'] ?? $this->rp_id, true )
			. chr( $overrides['flags'] ?? 0x05 )
			. pack( 'N', $this->sign_count );

		openssl_sign( $auth_data . hash( 'sha256', $client_data, true ), $signature, $this->key, OPENSSL_ALGO_SHA256 );
		if ( ! empty( $overrides['corrupt_signature'] ) ) {
			$last = strlen( $signature ) - 1;
			$signature[ $last ] = chr( ord( $signature[ $last ] ) ^ 0xff );
		}

		$id = Base64url::encode( $credential_id );

		return wp_json_encode(
			[
				'id' => $id,
				'rawId' => $id,
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64url::encode( $client_data ),
					'authenticatorData' => Base64url::encode( $auth_data ),
					'signature' => Base64url::encode( $signature ),
					'userHandle' => isset( $overrides['user_handle'] ) ? Base64url::encode( $overrides['user_handle'] ) : null,
				],
				'clientExtensionResults' => new stdClass(),
			]
		);
	}

	/**
	 * Mark a value as a CBOR byte string.
	 *
	 * @param string $data Binary data.
	 * @return stdClass
	 */
	public static function bytes( string $data ): stdClass {
		$value = new stdClass();
		$value->bytes = $data;
		return $value;
	}

	/**
	 * Encode a value as CBOR.
	 *
	 * Handles ints, text strings, byte strings (see bytes()), lists and maps. A
	 * PHP array that is not a list becomes a map, and so does a stdClass without
	 * a "bytes" property, which gives an empty map from `new stdClass()`.
	 *
	 * @param mixed $value Value to encode.
	 * @return string
	 * @throws \InvalidArgumentException For unsupported types.
	 */
	public static function cbor( $value ): string {
		if ( is_int( $value ) ) {
			return $value >= 0 ? self::cbor_head( 0, $value ) : self::cbor_head( 1, -1 - $value );
		}

		if ( is_string( $value ) ) {
			return self::cbor_head( 3, strlen( $value ) ) . $value;
		}

		if ( $value instanceof stdClass ) {
			if ( isset( $value->bytes ) ) {
				return self::cbor_head( 2, strlen( $value->bytes ) ) . $value->bytes;
			}
			return self::cbor_map( (array) $value );
		}

		if ( is_array( $value ) ) {
			if ( ! array_is_list( $value ) ) {
				return self::cbor_map( $value );
			}

			$out = self::cbor_head( 4, count( $value ) );
			foreach ( $value as $item ) {
				$out .= self::cbor( $item );
			}
			return $out;
		}

		throw new \InvalidArgumentException( 'Unsupported CBOR value.' ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
	}

	/**
	 * Encode a map.
	 *
	 * @param array $map Keys are ints or strings.
	 * @return string
	 */
	private static function cbor_map( array $map ): string {
		$out = self::cbor_head( 5, count( $map ) );
		foreach ( $map as $key => $item ) {
			$out .= self::cbor( $key ) . self::cbor( $item );
		}
		return $out;
	}

	/**
	 * Encode a CBOR initial byte and length.
	 *
	 * @param int $major  Major type, 0 to 7.
	 * @param int $length Argument.
	 * @return string
	 */
	private static function cbor_head( int $major, int $length ): string {
		$major <<= 5;
		if ( $length < 24 ) {
			return chr( $major | $length );
		}
		if ( $length < 256 ) {
			return chr( $major | 24 ) . chr( $length );
		}
		if ( $length < 65536 ) {
			return chr( $major | 25 ) . pack( 'n', $length );
		}
		return chr( $major | 26 ) . pack( 'N', $length );
	}

	/**
	 * Build clientDataJSON.
	 *
	 * @param string $type      Default ceremony type.
	 * @param string $challenge Challenge from the options.
	 * @param array  $overrides Overrides.
	 * @return string
	 */
	private function client_data( string $type, string $challenge, array $overrides ): string {
		return wp_json_encode(
			[
				'type' => $overrides['type'] ?? $type,
				'challenge' => $overrides['challenge'] ?? $challenge,
				'origin' => $overrides['origin'] ?? $this->origin,
				'crossOrigin' => $overrides['cross_origin'] ?? false,
			]
		);
	}
}
