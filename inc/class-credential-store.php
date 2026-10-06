<?php
/**
 * Passkey credential storage in user meta.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

/**
 * Reads and writes a user's passkeys.
 *
 * All credentials live in one meta value, keyed by base64url credential ID.
 */
class Credential_Store {

	/**
	 * User meta key holding the credentials.
	 */
	const META_KEY = '_two_factor_passkey_credentials';

	/**
	 * User meta key holding the opaque WebAuthn user handle.
	 */
	const HANDLE_META_KEY = '_two_factor_passkey_user_handle';

	/**
	 * Default maximum number of passkeys per user.
	 */
	const DEFAULT_LIMIT = 20;

	/**
	 * Maximum length of a passkey name, in characters.
	 */
	const NAME_MAX_LENGTH = 100;

	/**
	 * Fields that update() may change.
	 */
	const MUTABLE_FIELDS = [ 'name', 'sign_count', 'last_used_at', 'flagged_at', 'backed_up' ];

	/**
	 * Get all of a user's credentials.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, array> Credentials keyed by ID.
	 */
	public static function get_all( int $user_id ): array {
		$credentials = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $credentials ) ) {
			return [];
		}

		return array_filter(
			$credentials,
			function ( $credential, $id ) {
				return is_array( $credential )
					&& isset( $credential['id'] )
					&& isset( $credential['public_key'] )
					&& isset( $credential['rp_id'] )
					&& $credential['id'] === $id;
			},
			ARRAY_FILTER_USE_BOTH
		);
	}

	/**
	 * Get one credential.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Base64url credential ID.
	 * @return array|null
	 */
	public static function get( int $user_id, string $id ): ?array {
		return self::get_all( $user_id )[ $id ] ?? null;
	}

	/**
	 * Whether the user has any credentials at all.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function has_any( int $user_id ): bool {
		return self::get_all( $user_id ) !== [];
	}

	/**
	 * Get the credentials that can be used for login on this RP ID.
	 *
	 * @param int    $user_id User ID.
	 * @param string $rp_id   RP ID.
	 * @return array<string, array>
	 */
	public static function get_usable( int $user_id, string $rp_id ): array {
		return array_filter(
			self::get_all( $user_id ),
			function ( array $credential ) use ( $rp_id ) {
				return $credential['rp_id'] === $rp_id && empty( $credential['flagged_at'] );
			}
		);
	}

	/**
	 * Store a new credential.
	 *
	 * @param int   $user_id    User ID.
	 * @param array $credential Credential record, see docs/PLAN.md for the shape.
	 * @return bool False if a credential with this ID already exists.
	 */
	public static function add( int $user_id, array $credential ): bool {
		$credentials = self::get_all( $user_id );
		if ( isset( $credentials[ $credential['id'] ] ) ) {
			return false;
		}

		$credentials[ $credential['id'] ] = $credential;
		return (bool) update_user_meta( $user_id, self::META_KEY, $credentials );
	}

	/**
	 * Change fields on a stored credential.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Base64url credential ID.
	 * @param array  $changes Field values, limited to self::MUTABLE_FIELDS.
	 * @return bool False if the credential does not exist.
	 */
	public static function update( int $user_id, string $id, array $changes ): bool {
		$credentials = self::get_all( $user_id );
		if ( ! isset( $credentials[ $id ] ) ) {
			return false;
		}

		$changes = array_intersect_key( $changes, array_flip( self::MUTABLE_FIELDS ) );
		$updated = array_merge( $credentials[ $id ], $changes );
		if ( $updated === $credentials[ $id ] ) {
			return true;
		}

		$credentials[ $id ] = $updated;
		return (bool) update_user_meta( $user_id, self::META_KEY, $credentials );
	}

	/**
	 * Remove a credential.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Base64url credential ID.
	 * @return bool False if the credential does not exist.
	 */
	public static function delete( int $user_id, string $id ): bool {
		$credentials = self::get_all( $user_id );
		if ( ! isset( $credentials[ $id ] ) ) {
			return false;
		}

		unset( $credentials[ $id ] );
		if ( $credentials === [] ) {
			return delete_user_meta( $user_id, self::META_KEY );
		}

		return (bool) update_user_meta( $user_id, self::META_KEY, $credentials );
	}

	/**
	 * Get the user's opaque WebAuthn user handle, creating it on first use.
	 *
	 * @param int $user_id User ID.
	 * @return string Binary handle, 32 bytes.
	 */
	public static function get_user_handle( int $user_id ): string {
		$stored = get_user_meta( $user_id, self::HANDLE_META_KEY, true );
		$handle = is_string( $stored ) ? Base64url::decode( $stored ) : null;
		if ( $handle !== null && strlen( $handle ) === 32 ) {
			return $handle;
		}

		$handle = random_bytes( 32 );
		update_user_meta( $user_id, self::HANDLE_META_KEY, Base64url::encode( $handle ) );
		return $handle;
	}

	/**
	 * Get the maximum number of passkeys a user may have.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function get_limit( int $user_id ): int {
		/**
		 * Filters the maximum number of passkeys a user may register.
		 *
		 * @param int $limit   Maximum. Default 20.
		 * @param int $user_id User ID.
		 */
		return max( 1, (int) apply_filters( 'two_factor_passkey_credential_limit', self::DEFAULT_LIMIT, $user_id ) );
	}

	/**
	 * Clean a user-supplied passkey name.
	 *
	 * @param string $name Raw name.
	 * @return string Plain text, at most self::NAME_MAX_LENGTH characters. May be empty.
	 */
	public static function sanitize_name( string $name ): string {
		return trim( mb_substr( sanitize_text_field( $name ), 0, self::NAME_MAX_LENGTH ) );
	}

	/**
	 * Get the default name for the user's next passkey.
	 *
	 * @param int $user_id User ID.
	 * @return string
	 */
	public static function get_default_name( int $user_id ): string {
		/* translators: %d: number of the passkey, starting at 1. */
		return sprintf( __( 'Passkey %d', 'two-factor-passkey' ), count( self::get_all( $user_id ) ) + 1 );
	}
}
