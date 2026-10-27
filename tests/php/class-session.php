<?php
/**
 * Login session helper for tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use Two_Factor_Core;
use WP_Session_Tokens;

/**
 * Creates logged-in browser sessions.
 *
 * wp_set_current_user() sets no cookie, so wp_get_session_token() would be empty.
 * These helpers store a session token and put the matching logged-in cookie in
 * $_COOKIE, which is where Two Factor looks for the current session.
 */
trait Session {

	/**
	 * Logged-in cookie values keyed by user ID.
	 *
	 * @var array<int, string>
	 */
	private $session_cookies = [];

	/**
	 * Log a user in with a new session and make them the current user.
	 *
	 * @param int  $user_id    User ID.
	 * @param bool $two_factor Whether the session has passed two-factor login.
	 * @return string The session token.
	 */
	protected function start_session( int $user_id, bool $two_factor = true ): string {
		$expiration = time() + DAY_IN_SECONDS;
		$token = WP_Session_Tokens::get_instance( $user_id )->create( $expiration );

		$this->session_cookies[ $user_id ] = wp_generate_auth_cookie( $user_id, $expiration, 'logged_in', $token );
		$this->resume_session( $user_id );

		if ( $two_factor ) {
			Two_Factor_Core::update_current_user_session(
				[
					'two-factor-provider' => '',
					'two-factor-login' => time(),
				]
			);
		}

		return $token;
	}

	/**
	 * Make a user the current user, using their session if they have one.
	 *
	 * @param int $user_id User ID.
	 */
	protected function resume_session( int $user_id ): void {
		if ( ! isset( $this->session_cookies[ $user_id ] ) ) {
			$this->start_session( $user_id );
			return;
		}

		wp_set_current_user( $user_id );
		$_COOKIE[ LOGGED_IN_COOKIE ] = $this->session_cookies[ $user_id ];
	}

	/**
	 * Forget every session cookie.
	 */
	protected function end_sessions(): void {
		$this->session_cookies = [];
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	}
}
