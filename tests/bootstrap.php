<?php
/**
 * PHPUnit bootstrap for the Two Factor Passkey plugin.
 *
 * @package two-factor-passkey
 */

// phpcs:disable PSR1.Files.SideEffects

$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
	$_tests_dir = is_dir( '/wordpress-phpunit' ) ? '/wordpress-phpunit' : sys_get_temp_dir() . '/wordpress-tests-lib';
}

if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
	echo "Could not find {$_tests_dir}/includes/functions.php. Set WP_TESTS_DIR to the WordPress test library.\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	exit( 1 );
}

$_root_dir = dirname( __DIR__ );

// Composer autoloader, for the PHPUnit polyfills.
require_once $_root_dir . '/vendor/autoload.php';

if ( ! defined( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' ) ) {
	define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', $_root_dir . '/vendor/yoast/phpunit-polyfills' );
}

require_once $_tests_dir . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	function () use ( $_root_dir ) {
		require $_root_dir . '/vendor/humanmade/two-factor/two-factor.php';
		require $_root_dir . '/plugin.php';
	}
);

require $_tests_dir . '/includes/bootstrap.php';

require_once __DIR__ . '/php/class-site-url.php';
require_once __DIR__ . '/php/class-soft-authenticator.php';
