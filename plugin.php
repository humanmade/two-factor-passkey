<?php
/**
 * Plugin Name: Two Factor Passkey
 * Plugin URI: https://github.com/humanmade/two-factor-passkey
 * Description: Adds passkeys (WebAuthn) as a second-factor provider for the Human Made Two Factor plugin.
 * Version: 0.1.0
 * Requires at least: 6.6
 * Requires PHP: 8.2
 * Author: Human Made
 * Author URI: https://humanmade.com/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: two-factor-passkey
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

const VERSION = '0.1.0';
const PLUGIN_FILE = __FILE__;

require_once __DIR__ . '/vendor-prefixed/autoload.php';
require_once __DIR__ . '/inc/namespace.php';
require_once __DIR__ . '/inc/class-base64url.php';
require_once __DIR__ . '/inc/class-relying-party.php';
require_once __DIR__ . '/inc/class-challenge-store.php';
require_once __DIR__ . '/inc/class-credential-store.php';
require_once __DIR__ . '/inc/class-ceremony.php';

bootstrap();
