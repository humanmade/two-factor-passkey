<?php
/**
 * WebAuthn registration and authentication ceremonies.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- lbuchs/webauthn uses camelCase properties.

use HM\Two_Factor_Passkey\Vendor\lbuchs\WebAuthn\Attestation\AuthenticatorData;
use HM\Two_Factor_Passkey\Vendor\lbuchs\WebAuthn\WebAuthn;
use HM\Two_Factor_Passkey\Vendor\lbuchs\WebAuthn\WebAuthnException;
use Throwable;
use Two_Factor_Core;
use WP_Error;
use WP_User;

/**
 * Builds WebAuthn options and verifies browser responses.
 *
 * The WebAuthn library checks challenges, RP ID hashes, flags, signatures and
 * sign counters. This class adds what the library leaves to its caller: an
 * exact origin match, single-use challenges bound to the user, and checks that
 * the credential and user handle belong to the user.
 */
class Ceremony {

	/**
	 * Get options for navigator.credentials.create() and store the challenge.
	 *
	 * @param WP_User $user User adding a passkey.
	 * @return array|WP_Error PublicKeyCredentialCreationOptions as JSON-ready data.
	 */
	public static function get_creation_options( WP_User $user ) {
		if ( ! Relying_Party::is_secure_context() ) {
			return self::error( 'insecure_context' );
		}

		if ( count( Credential_Store::get_all( $user->ID ) ) >= Credential_Store::get_limit( $user->ID ) ) {
			return self::error( 'limit_reached' );
		}

		$exclude_ids = [];
		foreach ( Credential_Store::get_all( $user->ID ) as $credential ) {
			if ( $credential['rp_id'] === Relying_Party::get_id() ) {
				$exclude_ids[] = Base64url::decode( $credential['id'] );
			}
		}

		try {
			$server = self::create_server();
			$args = $server->getCreateArgs(
				Credential_Store::get_user_handle( $user->ID ),
				$user->user_login,
				$user->display_name !== '' ? $user->display_name : $user->user_login,
				Challenge_Store::get_ttl(),
				'discouraged',
				self::get_user_verification(),
				null,
				array_filter( $exclude_ids )
			);
		} catch ( Throwable $e ) {
			return self::error( 'server_error', $e );
		}

		$args->publicKey->attestation = 'none';
		unset( $args->publicKey->extensions );

		Challenge_Store::save( $user->ID, Challenge_Store::CREATE, $server->getChallenge()->getBinaryString() );

		return json_decode( wp_json_encode( $args->publicKey ), true );
	}

	/**
	 * Verify a navigator.credentials.create() response and store the passkey.
	 *
	 * @param WP_User $user     User adding a passkey.
	 * @param string  $response JSON from PublicKeyCredential.toJSON().
	 * @param string  $name     Name for the passkey. A default is used if empty.
	 * @return array|WP_Error The stored credential.
	 */
	public static function verify_registration( WP_User $user, string $response, string $name = '' ) {
		$challenge = Challenge_Store::consume( $user->ID, Challenge_Store::CREATE );
		if ( $challenge === null ) {
			return self::error( 'challenge_invalid' );
		}

		$data = self::decode_response( $response, [ 'clientDataJSON', 'attestationObject' ] );
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		if ( ! self::has_allowed_origin( $data['clientDataJSON'] ) ) {
			return self::error( 'origin_invalid' );
		}

		try {
			$result = self::create_server()->processCreate(
				$data['clientDataJSON'],
				$data['attestationObject'],
				$challenge,
				self::get_user_verification() === 'required',
				true,
				false
			);
		} catch ( Throwable $e ) {
			return self::error( 'verification_failed', $e );
		}

		$id = Base64url::encode( $result->credentialId );
		if ( ! hash_equals( $id, $data['id'] ) ) {
			return self::error( 'response_invalid' );
		}

		if ( Credential_Store::get( $user->ID, $id ) !== null ) {
			return self::error( 'duplicate' );
		}

		if ( count( Credential_Store::get_all( $user->ID ) ) >= Credential_Store::get_limit( $user->ID ) ) {
			return self::error( 'limit_reached' );
		}

		$name = Credential_Store::sanitize_name( $name );
		$credential = [
			'id' => $id,
			'public_key' => $result->credentialPublicKey,
			'sign_count' => (int) $result->signatureCounter,
			'rp_id' => Relying_Party::get_id(),
			'name' => $name !== '' ? $name : Credential_Store::get_default_name( $user->ID ),
			'aaguid' => self::format_aaguid( (string) $result->AAGUID ),
			'transports' => self::sanitize_transports( $data['transports'] ),
			'backup_eligible' => (bool) $result->isBackupEligible,
			'backed_up' => (bool) $result->isBackedUp,
			'user_verified' => (bool) $result->userVerified,
			'created_at' => time(),
			'last_used_at' => null,
			'flagged_at' => null,
		];

		if ( ! Credential_Store::add( $user->ID, $credential ) ) {
			return self::error( 'storage_failed' );
		}

		return $credential;
	}

	/**
	 * Get options for navigator.credentials.get() at the login step.
	 *
	 * Binds the challenge to the user's current Two Factor login nonce.
	 *
	 * @param WP_User $user User signing in.
	 * @return array|WP_Error PublicKeyCredentialRequestOptions as JSON-ready data.
	 */
	public static function get_request_options( WP_User $user ) {
		if ( ! Relying_Party::is_secure_context() ) {
			return self::error( 'insecure_context' );
		}

		$credentials = Credential_Store::get_usable( $user->ID, Relying_Party::get_id() );
		if ( $credentials === [] ) {
			return self::error( 'no_usable_credentials' );
		}

		$login_nonce = get_user_meta( $user->ID, Two_Factor_Core::USER_META_NONCE_KEY, true );
		if ( ! is_array( $login_nonce ) || empty( $login_nonce['key'] ) ) {
			return self::error( 'login_nonce_missing' );
		}

		try {
			$server = self::create_server();
			$args = $server->getGetArgs(
				array_filter( array_map( [ Base64url::class, 'decode' ], array_keys( $credentials ) ) ),
				Challenge_Store::get_ttl(),
				true,
				true,
				true,
				true,
				true,
				self::get_user_verification()
			);
		} catch ( Throwable $e ) {
			return self::error( 'server_error', $e );
		}

		Challenge_Store::save( $user->ID, Challenge_Store::GET, $server->getChallenge()->getBinaryString(), (string) $login_nonce['key'] );

		return json_decode( wp_json_encode( $args->publicKey ), true );
	}

	/**
	 * Verify a navigator.credentials.get() response for the login step.
	 *
	 * @param WP_User $user        User signing in.
	 * @param string  $response    JSON from PublicKeyCredential.toJSON().
	 * @param string  $login_nonce The Two Factor login nonce posted with the form.
	 * @return array|WP_Error The updated credential.
	 */
	public static function verify_assertion( WP_User $user, string $response, string $login_nonce ) {
		$challenge = Challenge_Store::consume( $user->ID, Challenge_Store::GET, $login_nonce );
		if ( $challenge === null ) {
			return self::error( 'challenge_invalid' );
		}

		$data = self::decode_response( $response, [ 'clientDataJSON', 'authenticatorData', 'signature' ] );
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$credential = Credential_Store::get( $user->ID, $data['id'] );
		if ( $credential === null || $credential['rp_id'] !== Relying_Party::get_id() ) {
			return self::error( 'credential_unknown' );
		}

		if ( ! empty( $credential['flagged_at'] ) ) {
			return self::error( 'credential_flagged' );
		}

		if ( $data['userHandle'] !== null && ! hash_equals( Credential_Store::get_user_handle( $user->ID ), $data['userHandle'] ) ) {
			return self::error( 'user_handle_mismatch' );
		}

		if ( ! self::has_allowed_origin( $data['clientDataJSON'] ) ) {
			return self::error( 'origin_invalid' );
		}

		$server = self::create_server();
		try {
			$server->processGet(
				$data['clientDataJSON'],
				$data['authenticatorData'],
				$data['signature'],
				$credential['public_key'],
				$challenge,
				(int) $credential['sign_count'],
				self::get_user_verification() === 'required',
				true
			);
		} catch ( WebAuthnException $e ) {
			if ( $e->getCode() === WebAuthnException::SIGNATURE_COUNTER ) {
				return self::flag_credential( $user, $credential, $e );
			}
			return self::error( 'verification_failed', $e );
		} catch ( Throwable $e ) {
			return self::error( 'verification_failed', $e );
		}

		$changes = [
			'sign_count' => $server->getSignatureCounter() ?? (int) $credential['sign_count'],
			'last_used_at' => time(),
		];
		try {
			$changes['backed_up'] = ( new AuthenticatorData( $data['authenticatorData'] ) )->getIsBackup();
		} catch ( Throwable $e ) {
			// The signature already covered this data, so a parse failure here only loses the flag.
			unset( $e );
		}

		Credential_Store::update( $user->ID, $credential['id'], $changes );

		return array_merge( $credential, $changes );
	}

	/**
	 * Mark a credential as possibly cloned after a sign counter regression.
	 *
	 * @param WP_User            $user       User signing in.
	 * @param array              $credential Credential that failed.
	 * @param WebAuthnException $e          Library exception.
	 * @return WP_Error
	 */
	private static function flag_credential( WP_User $user, array $credential, WebAuthnException $e ): WP_Error {
		$flagged_at = time();
		Credential_Store::update( $user->ID, $credential['id'], [ 'flagged_at' => $flagged_at ] );

		/**
		 * Fires when a passkey's sign counter goes backwards, which may mean the
		 * authenticator was cloned. The passkey is disabled and the login rejected.
		 *
		 * @param WP_User $user       User whose passkey was flagged.
		 * @param array   $credential The credential as it was before flagging.
		 */
		do_action( 'two_factor_passkey_counter_regression', $user, $credential );

		return self::error( 'credential_flagged', $e );
	}

	/**
	 * Create a WebAuthn server for the current RP ID.
	 *
	 * Attestation is requested as "none" and no root certificates are loaded,
	 * so no trust decision is made from attestation.
	 *
	 * @return WebAuthn
	 */
	private static function create_server(): WebAuthn {
		return new WebAuthn( Relying_Party::get_name(), Relying_Party::get_id(), null, true );
	}

	/**
	 * Get the user verification requirement.
	 *
	 * @return string "required" or "preferred".
	 */
	private static function get_user_verification(): string {
		/**
		 * Filters whether passkeys must verify the user (PIN or biometrics).
		 *
		 * @param bool $required Default false: verification is preferred, not required.
		 */
		return apply_filters( 'two_factor_passkey_require_user_verification', false ) ? 'required' : 'preferred';
	}

	/**
	 * Decode a PublicKeyCredential.toJSON() response.
	 *
	 * @param string   $response JSON string.
	 * @param string[] $fields   Required base64url fields inside "response".
	 * @return array|WP_Error Decoded binary fields plus "id", "userHandle" and "transports".
	 */
	private static function decode_response( string $response, array $fields ) {
		$json = json_decode( $response, true );
		if ( ! is_array( $json ) || ( $json['type'] ?? '' ) !== 'public-key' || ! is_string( $json['id'] ?? null ) || ! is_array( $json['response'] ?? null ) ) {
			return self::error( 'response_invalid' );
		}

		$raw_id = Base64url::decode( $json['id'] );
		if ( $raw_id === null || $raw_id === '' ) {
			return self::error( 'response_invalid' );
		}

		$data = [
			'id' => Base64url::encode( $raw_id ),
			'userHandle' => null,
			'transports' => [],
		];

		foreach ( $fields as $field ) {
			$value = $json['response'][ $field ] ?? null;
			$decoded = is_string( $value ) ? Base64url::decode( $value ) : null;
			if ( $decoded === null || $decoded === '' ) {
				return self::error( 'response_invalid' );
			}
			$data[ $field ] = $decoded;
		}

		$user_handle = $json['response']['userHandle'] ?? null;
		if ( is_string( $user_handle ) && $user_handle !== '' ) {
			$data['userHandle'] = Base64url::decode( $user_handle );
			if ( $data['userHandle'] === null ) {
				return self::error( 'response_invalid' );
			}
		}

		if ( isset( $json['response']['transports'] ) && is_array( $json['response']['transports'] ) ) {
			$data['transports'] = $json['response']['transports'];
		}

		return $data;
	}

	/**
	 * Check clientDataJSON's origin against the exact allowed list.
	 *
	 * @param string $client_data_json Raw clientDataJSON.
	 * @return bool
	 */
	private static function has_allowed_origin( string $client_data_json ): bool {
		$client_data = json_decode( $client_data_json, true );
		if ( ! is_array( $client_data ) || ! is_string( $client_data['origin'] ?? null ) ) {
			return false;
		}

		if ( ! empty( $client_data['crossOrigin'] ) ) {
			return false;
		}

		return Relying_Party::is_allowed_origin( $client_data['origin'] );
	}

	/**
	 * Keep only known transport names.
	 *
	 * @param array $transports Transports reported by the browser.
	 * @return string[]
	 */
	private static function sanitize_transports( array $transports ): array {
		$known = [ 'ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb' ];
		return array_values( array_intersect( $known, array_filter( $transports, 'is_string' ) ) );
	}

	/**
	 * Format a binary AAGUID as a UUID string.
	 *
	 * @param string $aaguid 16 bytes.
	 * @return string
	 */
	private static function format_aaguid( string $aaguid ): string {
		if ( strlen( $aaguid ) !== 16 ) {
			return '';
		}

		return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $aaguid ), 4 ) );
	}

	/**
	 * Build an error. Library details go to the error data, never the message.
	 *
	 * @param string         $code     Short error code, prefixed automatically.
	 * @param Throwable|null $previous Exception that caused it, if any.
	 * @return WP_Error
	 */
	private static function error( string $code, ?Throwable $previous = null ): WP_Error {
		$messages = [
			'insecure_context' => __( 'Passkeys need a secure (HTTPS) connection.', 'two-factor-passkey' ),
			'limit_reached' => __( 'You have reached the maximum number of passkeys. Remove one to add another.', 'two-factor-passkey' ),
			'no_usable_credentials' => __( 'None of your passkeys can be used on this site.', 'two-factor-passkey' ),
			'credential_flagged' => __( 'This passkey has been disabled because it may have been copied. Use another method, then remove it and add it again.', 'two-factor-passkey' ),
			'duplicate' => __( 'This passkey is already registered.', 'two-factor-passkey' ),
			'challenge_invalid' => __( 'The request expired. Please try again.', 'two-factor-passkey' ),
		];

		$data = [ 'status' => 400 ];
		if ( $previous !== null ) {
			$data['exception'] = get_class( $previous ) . ' (' . $previous->getCode() . '): ' . $previous->getMessage();
		}

		return new WP_Error(
			'two_factor_passkey_' . $code,
			$messages[ $code ] ?? __( 'The passkey could not be verified. Please try again.', 'two-factor-passkey' ),
			$data
		);
	}
}
