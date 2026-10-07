<?php
/**
 * REST routes for adding, listing, renaming and removing passkeys.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_User;

/**
 * Passkey management endpoints under two-factor-passkey/v1.
 */
class REST_Controller {

	/**
	 * Route namespace.
	 */
	const NAMESPACE = 'two-factor-passkey/v1';

	/**
	 * Register the routes.
	 */
	public static function register_routes(): void {
		$user_route = '/users/(?P<user_id>\d+)/passkeys';
		$user_arg = [
			'user_id' => [
				'type' => 'integer',
				'minimum' => 1,
				'required' => true,
			],
		];

		register_rest_route(
			self::NAMESPACE,
			$user_route,
			[
				[
					'methods' => WP_REST_Server::READABLE,
					'callback' => [ self::class, 'list_passkeys' ],
					'permission_callback' => [ self::class, 'can_manage' ],
					'args' => $user_arg,
				],
				[
					'methods' => WP_REST_Server::CREATABLE,
					'callback' => [ self::class, 'create_passkey' ],
					'permission_callback' => [ self::class, 'can_register' ],
					'args' => $user_arg + [
						'credential' => [
							'type' => 'object',
							'required' => true,
						],
						'name' => [
							'type' => 'string',
							'default' => '',
						],
					],
				],
			]
		);

		register_rest_route(
			self::NAMESPACE,
			$user_route . '/options',
			[
				'methods' => WP_REST_Server::CREATABLE,
				'callback' => [ self::class, 'get_creation_options' ],
				'permission_callback' => [ self::class, 'can_register' ],
				'args' => $user_arg,
			]
		);

		register_rest_route(
			self::NAMESPACE,
			$user_route . '/(?P<id>[A-Za-z0-9_-]+)',
			[
				'args' => $user_arg + [
					'id' => [
						'type' => 'string',
						'required' => true,
					],
				],
				[
					'methods' => WP_REST_Server::EDITABLE,
					'callback' => [ self::class, 'update_passkey' ],
					'permission_callback' => [ self::class, 'can_manage' ],
					'args' => [
						'name' => [
							'type' => 'string',
							'required' => true,
						],
					],
				],
				[
					'methods' => WP_REST_Server::DELETABLE,
					'callback' => [ self::class, 'delete_passkey' ],
					'permission_callback' => [ self::class, 'can_manage' ],
				],
			]
		);
	}

	/**
	 * Allow listing, renaming and removing passkeys for users you can edit.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return true|WP_Error
	 */
	public static function can_manage( WP_REST_Request $request ) {
		$check = self::check_session( $request );
		if ( is_wp_error( $check ) ) {
			return $check;
		}

		if ( ! current_user_can( 'edit_user', (int) $request['user_id'] ) ) {
			return self::forbidden();
		}

		if ( ! get_userdata( (int) $request['user_id'] ) ) {
			return new WP_Error(
				'two_factor_passkey_user_not_found',
				__( 'User not found.', 'two-factor-passkey' ),
				[ 'status' => 404 ]
			);
		}

		return true;
	}

	/**
	 * Allow adding passkeys only to your own account.
	 *
	 * A passkey created by someone else would live on their device, not the user's.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return true|WP_Error
	 */
	public static function can_register( WP_REST_Request $request ) {
		$check = self::can_manage( $request );
		if ( is_wp_error( $check ) ) {
			return $check;
		}

		if ( (int) $request['user_id'] !== get_current_user_id() ) {
			return new WP_Error(
				'two_factor_passkey_not_own_account',
				__( 'Only the user can add passkeys to their account.', 'two-factor-passkey' ),
				[ 'status' => 403 ]
			);
		}

		return true;
	}

	/**
	 * List a user's passkeys.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function list_passkeys( WP_REST_Request $request ): WP_REST_Response {
		$credentials = Credential_Store::get_all( (int) $request['user_id'] );
		return rest_ensure_response( array_values( array_map( [ self::class, 'prepare_item' ], $credentials ) ) );
	}

	/**
	 * Start registration: return creation options for navigator.credentials.create().
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function get_creation_options( WP_REST_Request $request ) {
		$options = Ceremony::get_creation_options( self::get_user( $request ) );
		return is_wp_error( $options ) ? $options : rest_ensure_response( $options );
	}

	/**
	 * Finish registration: verify the browser response and store the passkey.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function create_passkey( WP_REST_Request $request ) {
		$user = self::get_user( $request );
		$credential = Ceremony::verify_registration(
			$user,
			(string) wp_json_encode( $request['credential'] ),
			(string) $request['name']
		);
		if ( is_wp_error( $credential ) ) {
			return $credential;
		}

		enable_provider_for_user( $user->ID );

		$response = rest_ensure_response( self::prepare_item( $credential ) );
		$response->set_status( 201 );
		return $response;
	}

	/**
	 * Rename a passkey.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function update_passkey( WP_REST_Request $request ) {
		$user_id = (int) $request['user_id'];
		$id = (string) $request['id'];
		if ( Credential_Store::get( $user_id, $id ) === null ) {
			return self::not_found();
		}

		$name = Credential_Store::sanitize_name( (string) $request['name'] );
		if ( $name === '' ) {
			return new WP_Error(
				'two_factor_passkey_name_empty',
				__( 'Enter a name for the passkey.', 'two-factor-passkey' ),
				[ 'status' => 400 ]
			);
		}

		Credential_Store::update( $user_id, $id, [ 'name' => $name ] );
		return rest_ensure_response( self::prepare_item( Credential_Store::get( $user_id, $id ) ) );
	}

	/**
	 * Remove a passkey.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function delete_passkey( WP_REST_Request $request ) {
		$user_id = (int) $request['user_id'];
		$id = (string) $request['id'];
		$credential = Credential_Store::get( $user_id, $id );
		if ( $credential === null ) {
			return self::not_found();
		}

		Credential_Store::delete( $user_id, $id );

		return rest_ensure_response(
			[
				'deleted' => true,
				'previous' => self::prepare_item( $credential ),
			]
		);
	}

	/**
	 * Shape a stored credential for the browser. The public key is never sent.
	 *
	 * @param array $credential Stored credential.
	 * @return array
	 */
	public static function prepare_item( array $credential ): array {
		$date_format = get_option( 'date_format' );
		$last_used_at = $credential['last_used_at'] === null ? null : (int) $credential['last_used_at'];

		return [
			'id' => $credential['id'],
			'name' => $credential['name'],
			'created_at' => (int) $credential['created_at'],
			'created_label' => (string) wp_date( $date_format, (int) $credential['created_at'] ),
			'last_used_at' => $last_used_at,
			'last_used_label' => $last_used_at === null ? __( 'Never', 'two-factor-passkey' ) : (string) wp_date( $date_format, $last_used_at ),
			'flagged' => ! empty( $credential['flagged_at'] ),
			'backed_up' => (bool) $credential['backed_up'],
			'usable_here' => $credential['rp_id'] === Relying_Party::get_id(),
		];
	}

	/**
	 * Require a logged-in browser session with a valid REST nonce.
	 *
	 * Checking the nonce here, not only through cookie authentication, also
	 * refuses application passwords and any other non-browser authentication.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return true|WP_Error
	 */
	private static function check_session( WP_REST_Request $request ) {
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_not_logged_in',
				__( 'You must be logged in to manage passkeys.', 'two-factor-passkey' ),
				[ 'status' => 401 ]
			);
		}

		$nonce = (string) $request->get_header( 'X-WP-Nonce' );
		if ( rest_get_authenticated_app_password() !== null || $nonce === '' || ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
			return self::forbidden();
		}

		return true;
	}

	/**
	 * Get the user named in the route.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_User
	 */
	private static function get_user( WP_REST_Request $request ): WP_User {
		return get_userdata( (int) $request['user_id'] );
	}

	/**
	 * Build a 403 error.
	 *
	 * @return WP_Error
	 */
	private static function forbidden(): WP_Error {
		return new WP_Error(
			'rest_forbidden',
			__( 'Sorry, you are not allowed to manage passkeys for this user.', 'two-factor-passkey' ),
			[ 'status' => rest_authorization_required_code() ]
		);
	}

	/**
	 * Build a 404 error.
	 *
	 * @return WP_Error
	 */
	private static function not_found(): WP_Error {
		return new WP_Error(
			'two_factor_passkey_not_found',
			__( 'Passkey not found.', 'two-factor-passkey' ),
			[ 'status' => 404 ]
		);
	}
}
