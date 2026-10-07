<?php
/**
 * Deletes all passkey data when the plugin is deleted.
 *
 * @package HM\Two_Factor_Passkey
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/inc/namespace.php';
require_once __DIR__ . '/inc/class-credential-store.php';
require_once __DIR__ . '/inc/class-challenge-store.php';

HM\Two_Factor_Passkey\delete_all_data();
