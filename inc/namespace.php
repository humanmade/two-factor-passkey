<?php
/**
 * Plugin bootstrap and integration with the Two Factor plugin.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

use Two_Factor_Core;

/**
 * Provider key used by Two Factor. Stored in user meta, so it must never change.
 */
const PROVIDER_KEY = 'Two_Factor_Passkey';

/**
 * Hook the plugin into WordPress.
 */
function bootstrap(): void {
	add_action( 'plugins_loaded', __NAMESPACE__ . '\\load' );
}

/**
 * Register the provider, or show a notice when Two Factor is missing.
 */
function load(): void {
	if ( ! class_exists( 'Two_Factor_Provider' ) ) {
		add_action( 'admin_notices', __NAMESPACE__ . '\\missing_dependency_notice' );
		add_action( 'network_admin_notices', __NAMESPACE__ . '\\missing_dependency_notice' );
		return;
	}

	add_filter( 'two_factor_providers', __NAMESPACE__ . '\\register_provider' );
	add_action( 'init', __NAMESPACE__ . '\\register_assets' );
	add_action( 'rest_api_init', [ REST_Controller::class, 'register_routes' ] );
}

/**
 * Register the scripts and styles used on the profile and login screens.
 */
function register_assets(): void {
	$url = plugin_dir_url( PLUGIN_FILE ) . 'assets/';

	wp_register_script( 'two-factor-passkey-webauthn', $url . 'js/webauthn.js', [], VERSION, true );
	wp_register_script(
		'two-factor-passkey-profile',
		$url . 'js/profile.js',
		[ 'two-factor-passkey-webauthn', 'wp-api-fetch', 'wp-i18n', 'wp-a11y' ],
		VERSION,
		true
	);
	wp_register_script( 'two-factor-passkey-login', $url . 'js/login.js', [ 'two-factor-passkey-webauthn', 'wp-i18n' ], VERSION, true );
	wp_register_style( 'two-factor-passkey-profile', $url . 'css/profile.css', [], VERSION );
	wp_register_style( 'two-factor-passkey-login', $url . 'css/login.css', [ 'login' ], VERSION );

	wp_set_script_translations( 'two-factor-passkey-profile', 'two-factor-passkey' );
	wp_set_script_translations( 'two-factor-passkey-login', 'two-factor-passkey' );
}

/**
 * Add the passkey provider to the Two Factor provider list.
 *
 * @param array $providers Map of provider class name to class file path.
 * @return array
 */
function register_provider( array $providers ): array {
	$providers[ PROVIDER_KEY ] = __DIR__ . '/class-two-factor-passkey.php';
	return $providers;
}

/**
 * Tell administrators that the Two Factor plugin is required.
 */
function missing_dependency_notice(): void {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}

	printf(
		'<div class="notice notice-error"><p>%s</p></div>',
		esc_html__( 'Two Factor Passkey needs the Two Factor plugin. Passkeys are not available until it is active.', 'two-factor-passkey' )
	);
}

/**
 * Turn on the passkey provider for a user, if it is not already on.
 *
 * @param int $user_id User ID.
 */
function enable_provider_for_user( int $user_id ): void {
	$enabled = get_user_meta( $user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true );
	if ( ! is_array( $enabled ) ) {
		$enabled = [];
	}

	if ( in_array( PROVIDER_KEY, $enabled, true ) ) {
		return;
	}

	$enabled[] = PROVIDER_KEY;
	update_user_meta( $user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, $enabled );
}
