<?php
/**
 * Relying party ID, name and allowed origins.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

/**
 * Works out which RP ID and origins this site uses.
 *
 * Everything is derived from the configured site URLs, never from request headers.
 */
class Relying_Party {

	/**
	 * Get the RP ID: the host that serves the login screen and admin.
	 *
	 * @return string
	 */
	public static function get_id(): string {
		$rp_id = strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) );

		/**
		 * Filters the WebAuthn relying party ID.
		 *
		 * It must equal the login page's host or be a registrable suffix of it.
		 * Passkeys only work on sites that share the RP ID they were created with.
		 *
		 * @param string $rp_id Default RP ID, the host of site_url().
		 */
		return strtolower( (string) apply_filters( 'two_factor_passkey_rp_id', $rp_id ) );
	}

	/**
	 * Get the RP name shown by some authenticators.
	 *
	 * @return string
	 */
	public static function get_name(): string {
		$name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( $name === '' ) {
			$name = self::get_id();
		}

		/**
		 * Filters the WebAuthn relying party name.
		 *
		 * @param string $name Default name, the site title.
		 */
		return (string) apply_filters( 'two_factor_passkey_rp_name', $name );
	}

	/**
	 * Get the exact origins a ceremony may come from.
	 *
	 * @return string[]
	 */
	public static function get_allowed_origins(): array {
		$origins = array_filter(
			array_map(
				[ self::class, 'origin_from_url' ],
				[ site_url(), admin_url(), wp_login_url() ]
			)
		);

		/**
		 * Filters the origins WebAuthn responses are accepted from.
		 *
		 * Each origin is "scheme://host" with ":port" only for a non-default port.
		 *
		 * @param string[] $origins Origins built from site_url(), admin_url() and wp_login_url().
		 */
		$origins = (array) apply_filters( 'two_factor_passkey_allowed_origins', array_values( array_unique( $origins ) ) );

		return array_values( array_filter( $origins, 'is_string' ) );
	}

	/**
	 * Check an origin from clientDataJSON against the allowed list.
	 *
	 * @param string $origin Origin reported by the browser.
	 * @return bool
	 */
	public static function is_allowed_origin( string $origin ): bool {
		return in_array( $origin, self::get_allowed_origins(), true );
	}

	/**
	 * Build a browser-style origin from a URL.
	 *
	 * @param string $url Absolute URL.
	 * @return string|null Origin, or null if the URL has no scheme or host.
	 */
	public static function origin_from_url( string $url ): ?string {
		$parts = wp_parse_url( $url );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return null;
		}

		$scheme = strtolower( $parts['scheme'] );
		$origin = $scheme . '://' . strtolower( $parts['host'] );

		$default_ports = [
			'http' => 80,
			'https' => 443,
		];
		if ( isset( $parts['port'] ) && ( $default_ports[ $scheme ] ?? null ) !== (int) $parts['port'] ) {
			$origin .= ':' . (int) $parts['port'];
		}

		return $origin;
	}

	/**
	 * Whether browsers allow WebAuthn on this site.
	 *
	 * That needs HTTPS on the login and admin screens, where the ceremonies
	 * run, except on localhost. The WebAuthn library also only accepts plain
	 * HTTP when the RP ID is exactly "localhost".
	 *
	 * @return bool
	 */
	public static function is_secure_context(): bool {
		$login_scheme = wp_parse_url( wp_login_url(), PHP_URL_SCHEME );
		$admin_scheme = wp_parse_url( admin_url(), PHP_URL_SCHEME );
		if ( $login_scheme === 'https' && $admin_scheme === 'https' ) {
			return true;
		}

		return self::get_id() === 'localhost';
	}
}
