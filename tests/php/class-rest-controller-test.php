<?php
/**
 * REST controller tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Challenge_Store;
use HM\Two_Factor_Passkey\Credential_Store;
use HM\Two_Factor_Passkey\REST_Controller;
use Two_Factor_Core;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Tests for the passkey REST routes.
 */
class REST_Controller_Test extends WP_UnitTestCase {

	use Site_Url;

	/**
	 * Administrator ID.
	 *
	 * @var int
	 */
	private $admin_id;

	/**
	 * Editor ID.
	 *
	 * @var int
	 */
	private $editor_id;

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$this->admin_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		if ( is_multisite() ) {
			// Only super admins can edit other users on a network.
			grant_super_admin( $this->admin_id );
		}
		$this->editor_id = self::factory()->user->create( [ 'role' => 'editor' ] );
	}

	public function tear_down() {
		unset( $GLOBALS['wp_rest_application_password_uuid'] );

		parent::tear_down();
	}

	/**
	 * Dispatch a request as a user with a valid REST nonce.
	 *
	 * @param string   $method  HTTP method.
	 * @param int      $user_id Route user ID.
	 * @param string   $suffix  Route suffix, such as "/options".
	 * @param array    $params  Body parameters.
	 * @param int|null $acting_user_id Current user ID, defaults to the administrator.
	 * @return \WP_REST_Response
	 */
	private function request( string $method, int $user_id, string $suffix = '', array $params = [], ?int $acting_user_id = null ) {
		wp_set_current_user( $acting_user_id ?? $this->admin_id );

		$request = new WP_REST_Request( $method, "/two-factor-passkey/v1/users/{$user_id}/passkeys{$suffix}" );
		$request->set_header( 'X-WP-Nonce', wp_create_nonce( 'wp_rest' ) );
		$request->set_body_params( $params );

		return rest_get_server()->dispatch( $request );
	}

	/**
	 * Assert the status and error code of a response.
	 *
	 * @param int    $status   HTTP status.
	 * @param string $code     Error code.
	 * @param mixed  $response Response.
	 */
	private function assert_error( int $status, string $code, $response ) {
		$this->assertSame( $status, $response->get_status() );
		$this->assertSame( $code, $response->get_data()['code'] );
	}

	/**
	 * Store a credential directly.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $id        Credential ID.
	 * @param array  $overrides Fields to override.
	 * @return array
	 */
	private function add_credential( int $user_id, string $id, array $overrides = [] ): array {
		$credential = array_merge(
			[
				'id' => $id,
				'public_key' => '-----BEGIN PUBLIC KEY-----secret',
				'sign_count' => 0,
				'rp_id' => 'example.org',
				'name' => 'Key ' . $id,
				'aaguid' => '00000000-0000-0000-0000-000000000000',
				'transports' => [ 'internal' ],
				'backup_eligible' => false,
				'backed_up' => false,
				'user_verified' => true,
				'created_at' => time(),
				'last_used_at' => null,
				'flagged_at' => null,
			],
			$overrides
		);
		Credential_Store::add( $user_id, $credential );

		return $credential;
	}

	/**
	 * Run the options step and build a creation response for the administrator.
	 *
	 * @param Soft_Authenticator $authenticator Authenticator.
	 * @param array              $overrides     Response overrides.
	 * @return array
	 */
	private function creation_response( Soft_Authenticator $authenticator, array $overrides = [] ): array {
		$options = $this->request( 'POST', $this->admin_id, '/options' );
		$this->assertSame( 200, $options->get_status() );

		return json_decode( $authenticator->create( $options->get_data(), $overrides ), true );
	}

	public function test_routes_are_registered() {
		$routes = rest_get_server()->get_routes();
		$base = '/two-factor-passkey/v1/users/(?P<user_id>\d+)/passkeys';

		$this->assertArrayHasKey( $base, $routes );
		$this->assertArrayHasKey( $base . '/options', $routes );
		$this->assertArrayHasKey( $base . '/(?P<id>[A-Za-z0-9_-]+)', $routes );

		$methods = [];
		foreach ( $routes[ $base ] as $handler ) {
			$methods = array_merge( $methods, array_keys( $handler['methods'] ) );
		}
		$this->assertContains( 'GET', $methods );
		$this->assertContains( 'POST', $methods );

		$methods = [];
		foreach ( $routes[ $base . '/(?P<id>[A-Za-z0-9_-]+)' ] as $handler ) {
			$methods = array_merge( $methods, array_keys( $handler['methods'] ) );
		}
		$this->assertContains( 'PATCH', $methods );
		$this->assertContains( 'DELETE', $methods );
	}

	public function test_logged_out_is_unauthorised() {
		wp_set_current_user( 0 );
		$request = new WP_REST_Request( 'GET', "/two-factor-passkey/v1/users/{$this->admin_id}/passkeys" );

		$response = rest_get_server()->dispatch( $request );

		$this->assert_error( 401, 'rest_not_logged_in', $response );
	}

	public function test_missing_nonce_is_forbidden() {
		wp_set_current_user( $this->admin_id );
		$request = new WP_REST_Request( 'GET', "/two-factor-passkey/v1/users/{$this->admin_id}/passkeys" );

		$response = rest_get_server()->dispatch( $request );

		$this->assert_error( 403, 'rest_forbidden', $response );
	}

	public function test_invalid_nonce_is_forbidden() {
		wp_set_current_user( $this->admin_id );
		$request = new WP_REST_Request( 'GET', "/two-factor-passkey/v1/users/{$this->admin_id}/passkeys" );
		$request->set_header( 'X-WP-Nonce', 'invalid' );

		$response = rest_get_server()->dispatch( $request );

		$this->assert_error( 403, 'rest_forbidden', $response );
	}

	public function test_application_password_is_forbidden() {
		$GLOBALS['wp_rest_application_password_uuid'] = wp_generate_uuid4();

		$response = $this->request( 'GET', $this->admin_id );

		$this->assert_error( 403, 'rest_forbidden', $response );
	}

	public function test_editor_cannot_list_administrators_passkeys() {
		$response = $this->request( 'GET', $this->admin_id, '', [], $this->editor_id );

		$this->assert_error( 403, 'rest_forbidden', $response );
	}

	public function test_administrator_can_list_editors_passkeys() {
		$this->add_credential( $this->editor_id, 'editorkey' );

		$response = $this->request( 'GET', $this->editor_id );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( [ 'editorkey' ], array_column( $response->get_data(), 'id' ) );
	}

	public function test_user_can_list_their_own_passkeys() {
		$this->add_credential( $this->editor_id, 'ownkey' );

		$response = $this->request( 'GET', $this->editor_id, '', [], $this->editor_id );

		$this->assertSame( 200, $response->get_status() );
		$this->assertCount( 1, $response->get_data() );
	}

	public function test_list_items_have_exactly_the_public_keys() {
		$this->add_credential( $this->admin_id, 'one' );
		$this->add_credential( $this->admin_id, 'two' );

		$data = $this->request( 'GET', $this->admin_id )->get_data();

		$this->assertCount( 2, $data );
		foreach ( $data as $item ) {
			$this->assertSame(
				[ 'id', 'name', 'created_at', 'created_label', 'last_used_at', 'last_used_label', 'flagged', 'backed_up', 'usable_here' ],
				array_keys( $item )
			);
			$this->assertArrayNotHasKey( 'public_key', $item );
			$this->assertArrayNotHasKey( 'rp_id', $item );
		}
	}

	public function test_administrator_gets_not_found_for_an_unknown_user() {
		$this->assert_error( 404, 'two_factor_passkey_user_not_found', $this->request( 'GET', 999999 ) );
	}

	public function test_editor_gets_forbidden_for_an_unknown_user() {
		$this->assert_error( 403, 'rest_forbidden', $this->request( 'GET', 999999, '', [], $this->editor_id ) );
	}

	public function test_options_for_own_account() {
		$response = $this->request( 'POST', $this->admin_id, '/options' );
		$data = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertNotEmpty( $data['challenge'] );
		$this->assertNotEmpty( $data['user']['id'] );
	}

	public function test_options_for_another_account_are_refused() {
		$response = $this->request( 'POST', $this->editor_id, '/options' );

		$this->assert_error( 403, 'two_factor_passkey_not_own_account', $response );
	}

	public function test_create_for_another_account_is_refused() {
		$response = $this->request( 'POST', $this->editor_id, '', [ 'credential' => [ 'id' => 'x' ] ] );

		$this->assert_error( 403, 'two_factor_passkey_not_own_account', $response );
	}

	public function test_create_flow_stores_the_passkey_and_enables_the_provider() {
		update_user_meta( $this->admin_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, [ 'Two_Factor_Email' ] );
		$authenticator = new Soft_Authenticator();

		$response = $this->request(
			'POST',
			$this->admin_id,
			'',
			[
				'credential' => $this->creation_response( $authenticator ),
				'name' => 'Laptop',
			]
		);
		$data = $response->get_data();

		$this->assertSame( 201, $response->get_status() );
		$this->assertSame( $authenticator->get_id(), $data['id'] );
		$this->assertSame( 'Laptop', $data['name'] );
		$this->assertTrue( $data['usable_here'] );
		$this->assertNotNull( Credential_Store::get( $this->admin_id, $authenticator->get_id() ) );
		$this->assertSame(
			[ 'Two_Factor_Email', 'Two_Factor_Passkey' ],
			get_user_meta( $this->admin_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true )
		);
	}

	public function test_create_with_a_bad_response_returns_the_ceremony_error() {
		$credential = $this->creation_response( new Soft_Authenticator(), [ 'origin' => 'https://evil.example' ] );

		$response = $this->request( 'POST', $this->admin_id, '', [ 'credential' => $credential ] );

		$this->assert_error( 400, 'two_factor_passkey_origin_invalid', $response );
		$this->assertFalse( Credential_Store::has_any( $this->admin_id ) );
		$this->assertEmpty( get_user_meta( $this->admin_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true ) );
	}

	public function test_create_without_options_returns_challenge_invalid() {
		$options = Ceremony::get_creation_options( get_user_by( 'id', $this->admin_id ) );
		Challenge_Store::consume( $this->admin_id, Challenge_Store::CREATE );
		$credential = json_decode( ( new Soft_Authenticator() )->create( $options ), true );

		$response = $this->request( 'POST', $this->admin_id, '', [ 'credential' => $credential ] );

		$this->assert_error( 400, 'two_factor_passkey_challenge_invalid', $response );
	}

	public function test_rename() {
		$this->add_credential( $this->admin_id, 'abc' );

		$response = $this->request( 'PATCH', $this->admin_id, '/abc', [ 'name' => 'Phone' ] );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 'Phone', $response->get_data()['name'] );
		$this->assertSame( 'Phone', Credential_Store::get( $this->admin_id, 'abc' )['name'] );
	}

	public function test_rename_sanitises_the_name() {
		$this->add_credential( $this->admin_id, 'abc' );

		$response = $this->request( 'PATCH', $this->admin_id, '/abc', [ 'name' => '<b>Phone</b><script>alert(1)</script>' ] );

		$this->assertSame( 200, $response->get_status() );
		$this->assertStringNotContainsString( '<', $response->get_data()['name'] );
		$this->assertStringStartsWith( 'Phone', $response->get_data()['name'] );
	}

	public function test_rename_to_an_empty_name_is_rejected() {
		$this->add_credential( $this->admin_id, 'abc', [ 'name' => 'Original' ] );

		foreach ( [ '', '   ', '<b></b>' ] as $name ) {
			$this->assert_error( 400, 'two_factor_passkey_name_empty', $this->request( 'PATCH', $this->admin_id, '/abc', [ 'name' => $name ] ) );
		}

		$this->assertSame( 'Original', Credential_Store::get( $this->admin_id, 'abc' )['name'] );
	}

	public function test_rename_unknown_id_is_not_found() {
		$this->assert_error( 404, 'two_factor_passkey_not_found', $this->request( 'PATCH', $this->admin_id, '/nope', [ 'name' => 'x' ] ) );
	}

	public function test_rename_another_users_credential_through_your_own_route_is_not_found() {
		$this->add_credential( $this->editor_id, 'editorkey', [ 'name' => 'Editor key' ] );

		$response = $this->request( 'PATCH', $this->admin_id, '/editorkey', [ 'name' => 'Hijacked' ] );

		$this->assert_error( 404, 'two_factor_passkey_not_found', $response );
		$this->assertSame( 'Editor key', Credential_Store::get( $this->editor_id, 'editorkey' )['name'] );
	}

	public function test_delete() {
		$this->add_credential( $this->admin_id, 'abc', [ 'name' => 'Old' ] );

		$response = $this->request( 'DELETE', $this->admin_id, '/abc' );
		$data = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertTrue( $data['deleted'] );
		$this->assertSame( 'abc', $data['previous']['id'] );
		$this->assertSame( 'Old', $data['previous']['name'] );
		$this->assertNull( Credential_Store::get( $this->admin_id, 'abc' ) );
	}

	public function test_delete_unknown_id_is_not_found() {
		$this->assert_error( 404, 'two_factor_passkey_not_found', $this->request( 'DELETE', $this->admin_id, '/nope' ) );
	}

	public function test_administrator_can_delete_an_editors_passkey() {
		$this->add_credential( $this->editor_id, 'editorkey' );
		$this->add_credential( $this->admin_id, 'adminkey' );

		$response = $this->request( 'DELETE', $this->editor_id, '/editorkey' );

		$this->assertSame( 200, $response->get_status() );
		$this->assertFalse( Credential_Store::has_any( $this->editor_id ) );
		$this->assertNotNull( Credential_Store::get( $this->admin_id, 'adminkey' ) );
	}

	public function test_editor_cannot_delete_an_administrators_passkey() {
		$this->add_credential( $this->admin_id, 'adminkey' );

		$response = $this->request( 'DELETE', $this->admin_id, '/adminkey', [], $this->editor_id );

		$this->assert_error( 403, 'rest_forbidden', $response );
		$this->assertNotNull( Credential_Store::get( $this->admin_id, 'adminkey' ) );
	}

	public function test_prepare_item_labels_unused_keys_as_never() {
		$item = REST_Controller::prepare_item( $this->add_credential( $this->admin_id, 'abc' ) );

		$this->assertNull( $item['last_used_at'] );
		$this->assertSame( 'Never', $item['last_used_label'] );
		$this->assertFalse( $item['flagged'] );
	}

	public function test_prepare_item_labels_used_keys_with_a_date() {
		$used = time() - DAY_IN_SECONDS;
		$item = REST_Controller::prepare_item( $this->add_credential( $this->admin_id, 'abc', [ 'last_used_at' => $used ] ) );

		$this->assertSame( $used, $item['last_used_at'] );
		$this->assertSame( wp_date( get_option( 'date_format' ), $used ), $item['last_used_label'] );
	}

	public function test_prepare_item_marks_other_rp_ids_as_not_usable_here() {
		$here = REST_Controller::prepare_item( $this->add_credential( $this->admin_id, 'here' ) );
		$other = REST_Controller::prepare_item( $this->add_credential( $this->admin_id, 'other', [ 'rp_id' => 'other.example' ] ) );

		$this->assertTrue( $here['usable_here'] );
		$this->assertFalse( $other['usable_here'] );
	}
}
