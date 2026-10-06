<?php
/**
 * Single-use, short-lived WebAuthn challenges.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

/**
 * Stores one pending challenge per user and ceremony in user meta.
 */
class Challenge_Store {

	/**
	 * Registration ceremony.
	 */
	const CREATE = 'create';

	/**
	 * Authentication ceremony.
	 */
	const GET = 'get';

	/**
	 * User meta key prefix. The ceremony name is appended.
	 */
	const META_KEY_PREFIX = '_two_factor_passkey_challenge_';

	/**
	 * Default lifetime in seconds.
	 */
	const DEFAULT_TTL = 300;

	/**
	 * Get the challenge lifetime in seconds. Also used as the browser timeout.
	 *
	 * @return int
	 */
	public static function get_ttl(): int {
		/**
		 * Filters how long a WebAuthn challenge stays valid, in seconds.
		 *
		 * @param int $ttl Lifetime in seconds. Default 300.
		 */
		return max( 30, (int) apply_filters( 'two_factor_passkey_challenge_ttl', self::DEFAULT_TTL ) );
	}

	/**
	 * Store a new challenge, replacing any pending one for the same ceremony.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $ceremony  self::CREATE or self::GET.
	 * @param string $challenge Binary challenge.
	 * @param string $nonce     Optional login nonce to bind the challenge to.
	 */
	public static function save( int $user_id, string $ceremony, string $challenge, string $nonce = '' ): void {
		self::assert_ceremony( $ceremony );

		update_user_meta(
			$user_id,
			self::META_KEY_PREFIX . $ceremony,
			[
				'challenge' => Base64url::encode( $challenge ),
				'expires' => time() + self::get_ttl(),
				'rp_id' => Relying_Party::get_id(),
				'nonce_hash' => $nonce === '' ? '' : self::hash_nonce( $nonce ),
			]
		);
	}

	/**
	 * Take the pending challenge, deleting it so it can only be used once.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $ceremony self::CREATE or self::GET.
	 * @param string $nonce    The login nonce, required if the challenge was bound to one.
	 * @return string|null Binary challenge, or null if missing, expired, for another RP ID or nonce.
	 */
	public static function consume( int $user_id, string $ceremony, string $nonce = '' ): ?string {
		self::assert_ceremony( $ceremony );

		$key = self::META_KEY_PREFIX . $ceremony;
		$stored = get_user_meta( $user_id, $key, true );
		delete_user_meta( $user_id, $key );

		if ( ! is_array( $stored ) ) {
			return null;
		}

		foreach ( [ 'challenge', 'expires', 'rp_id', 'nonce_hash' ] as $field ) {
			if ( ! isset( $stored[ $field ] ) ) {
				return null;
			}
		}

		if ( time() > (int) $stored['expires'] ) {
			return null;
		}

		if ( ! hash_equals( (string) $stored['rp_id'], Relying_Party::get_id() ) ) {
			return null;
		}

		if ( $stored['nonce_hash'] !== '' && ( $nonce === '' || ! hash_equals( (string) $stored['nonce_hash'], self::hash_nonce( $nonce ) ) ) ) {
			return null;
		}

		return Base64url::decode( (string) $stored['challenge'] );
	}

	/**
	 * Hash a login nonce so the raw value is not stored twice.
	 *
	 * @param string $nonce Login nonce.
	 * @return string
	 */
	private static function hash_nonce( string $nonce ): string {
		return hash_hmac( 'sha256', $nonce, wp_salt( 'nonce' ) );
	}

	/**
	 * Reject unknown ceremony names.
	 *
	 * @param string $ceremony Ceremony name.
	 * @throws \InvalidArgumentException If the ceremony is unknown.
	 */
	private static function assert_ceremony( string $ceremony ): void {
		if ( ! in_array( $ceremony, [ self::CREATE, self::GET ], true ) ) {
			throw new \InvalidArgumentException( 'Unknown WebAuthn ceremony.' );
		}
	}
}
