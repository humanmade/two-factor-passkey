<?php
/**
 * Multisite tests. Skipped unless the suite runs in multisite mode.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Challenge_Store;
use HM\Two_Factor_Passkey\Credential_Store;
use HM\Two_Factor_Passkey\Relying_Party;
use HM\Two_Factor_Passkey\REST_Controller;
use Two_Factor_Core;
use Two_Factor_Passkey;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Tests for passkeys on a multisite network.
 */
class Multisite_Test extends WP_UnitTestCase {

	/**
	 * Site URLs by blog ID.
	 *
	 * @var string[]
	 */
	private $site_urls = [];

	/**
	 * Subsite ID.
	 *
	 * @var int
	 */
	private $subsite_id;

	/**
	 * Network user ID.
	 *
	 * @var int
	 */
	private $user_id;

	public function set_up() {
		parent::set_up();

		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}

		$this->subsite_id = self::factory()->blog->create(
			[
				'domain' => 'sub.example.org',
				'path' => '/',
			]
		);
		$this->site_urls = [
			get_main_site_id() => 'https://example.org',
			$this->subsite_id => 'https://sub.example.org',
		];

		// WordPress builds URLs with the scheme of the current request.
		$_SERVER['HTTPS'] = 'on';
		$filter = function () {
			return $this->site_urls[ get_current_blog_id() ] ?? false;
		};
		add_filter( 'pre_option_siteurl', $filter, 11 );
		add_filter( 'pre_option_home', $filter, 11 );

		$this->user_id = self::factory()->user->create();
		add_user_to_blog( $this->subsite_id, $this->user_id, 'editor' );
		$_POST = [];
	}

	public function tear_down() {
		unset( $_SERVER['HTTPS'] );
		unset( $GLOBALS['wp_rest_application_password_uuid'] );

		parent::tear_down();
	}

	/**
	 * Register a passkey for a user on the current site.
	 *
	 * @param int                $user_id       User ID.
	 * @param Soft_Authenticator $authenticator Authenticator.
	 */
	private function register( int $user_id, Soft_Authenticator $authenticator ) {
		$user = get_user_by( 'id', $user_id );
		$options = Ceremony::get_creation_options( $user );
		$this->assertIsArray( $options );
		$this->assertIsArray( Ceremony::verify_registration( $user, $authenticator->create( $options ) ) );
	}

	/**
	 * Make the RP ID the network domain on every site.
	 */
	private function use_network_rp_id() {
		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'example.org';
			}
		);
	}

	/**
	 * Register a passkey on the main site, then switch to the subsite.
	 *
	 * @return Soft_Authenticator
	 */
	private function register_on_main_and_switch(): Soft_Authenticator {
		$authenticator = new Soft_Authenticator( 'example.org', 'https://example.org' );
		$this->register( $this->user_id, $authenticator );
		switch_to_blog( $this->subsite_id );

		return $authenticator;
	}

	/**
	 * Dispatch a REST request on the current site as a user with a valid nonce.
	 *
	 * @param string $method        HTTP method.
	 * @param int    $user_id       Route user ID.
	 * @param string $id            Credential ID.
	 * @param int    $acting_user_id Current user ID.
	 * @param array  $params        Body parameters.
	 * @return \WP_REST_Response
	 */
	private function request( string $method, int $user_id, string $id, int $acting_user_id, array $params = [] ) {
		wp_set_current_user( $acting_user_id );

		$request = new WP_REST_Request( $method, "/two-factor-passkey/v1/users/{$user_id}/passkeys/{$id}" );
		$request->set_header( 'X-WP-Nonce', wp_create_nonce( 'wp_rest' ) );
		$request->set_body_params( $params );

		return rest_get_server()->dispatch( $request );
	}

	/**
	 * Store a credential directly.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Credential ID.
	 */
	private function add_credential( int $user_id, string $id ) {
		Credential_Store::add(
			$user_id,
			[
				'id' => $id,
				'public_key' => '-----BEGIN PUBLIC KEY-----secret',
				'sign_count' => 0,
				'rp_id' => 'sub.example.org',
				'name' => 'Key ' . $id,
				'aaguid' => '00000000-0000-0000-0000-000000000000',
				'transports' => [ 'internal' ],
				'backup_eligible' => false,
				'backed_up' => false,
				'user_verified' => true,
				'created_at' => time(),
				'last_used_at' => null,
				'flagged_at' => null,
			]
		);
	}

	public function test_credentials_are_not_usable_on_a_subsite_with_another_host() {
		$authenticator = $this->register_on_main_and_switch();
		$user = get_user_by( 'id', $this->user_id );

		$this->assertSame( 'sub.example.org', Relying_Party::get_id() );
		$this->assertTrue( Two_Factor_Passkey::get_instance()->is_available_for_user( $user ) );
		$this->assertSame( [ $authenticator->get_id() ], array_keys( Credential_Store::get_all( $this->user_id ) ) );
		$this->assertSame( [], Credential_Store::get_usable( $this->user_id, Relying_Party::get_id() ) );

		Two_Factor_Core::create_login_nonce( $this->user_id );
		$options = Ceremony::get_request_options( $user );
		$this->assertWPError( $options );
		$this->assertSame( 'two_factor_passkey_no_usable_credentials', $options->get_error_code() );
	}

	public function test_network_rp_id_filter_lets_a_main_site_credential_log_in_on_the_subsite() {
		$authenticator = $this->register_on_main_and_switch();
		$this->use_network_rp_id();
		$user = get_user_by( 'id', $this->user_id );
		$authenticator->origin = 'https://sub.example.org';

		$this->assertSame( 'example.org', Relying_Party::get_id() );
		$nonce = Two_Factor_Core::create_login_nonce( $this->user_id )['key'];
		$options = Ceremony::get_request_options( $user );
		$this->assertIsArray( $options );
		$this->assertSame( 'example.org', $options['rpId'] );

		$result = Ceremony::verify_assertion( $user, $authenticator->get( $options ), $nonce );

		$this->assertIsArray( $result );
		$this->assertSame( 1, Credential_Store::get( $this->user_id, $authenticator->get_id() )['sign_count'] );
	}

	public function test_subsite_passkey_stores_its_own_host_and_is_not_usable_on_the_main_site() {
		switch_to_blog( $this->subsite_id );
		$authenticator = new Soft_Authenticator( 'sub.example.org', 'https://sub.example.org' );
		$this->register( $this->user_id, $authenticator );
		$credential = Credential_Store::get( $this->user_id, $authenticator->get_id() );
		$this->assertSame( 'sub.example.org', $credential['rp_id'] );
		$this->assertTrue( REST_Controller::prepare_item( $credential )['usable_here'] );
		restore_current_blog();

		$this->assertSame( 'example.org', Relying_Party::get_id() );
		$listed = REST_Controller::prepare_item( Credential_Store::get( $this->user_id, $authenticator->get_id() ) );
		$this->assertFalse( $listed['usable_here'] );
		$this->assertSame( [], Credential_Store::get_usable( $this->user_id, Relying_Party::get_id() ) );
	}

	public function test_delete_all_data_clears_users_on_every_site() {
		$main_user_id = self::factory()->user->create();
		add_user_to_blog( get_main_site_id(), $main_user_id, 'subscriber' );
		$this->add_credential( $main_user_id, 'mainkey' );
		$this->add_credential( $this->user_id, 'subkey' );
		Credential_Store::get_user_handle( $main_user_id );
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, random_bytes( 32 ) );
		update_user_meta( $this->user_id, 'unrelated_meta', 'keep me' );

		switch_to_blog( $this->subsite_id );
		\HM\Two_Factor_Passkey\delete_all_data();
		restore_current_blog();

		foreach ( [ $main_user_id, $this->user_id ] as $user_id ) {
			$this->assertSame( [], get_user_meta( $user_id, Credential_Store::META_KEY ) );
			$this->assertSame( [], get_user_meta( $user_id, Credential_Store::HANDLE_META_KEY ) );
			$this->assertSame( [], get_user_meta( $user_id, Challenge_Store::META_KEY_PREFIX . Challenge_Store::GET ) );
		}
		$this->assertSame( 'keep me', get_user_meta( $this->user_id, 'unrelated_meta', true ) );
	}

	public function test_super_admin_can_rename_and_remove_a_subsite_users_passkey() {
		$super_admin_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		grant_super_admin( $super_admin_id );
		$this->add_credential( $this->user_id, 'subkey' );
		switch_to_blog( $this->subsite_id );

		$response = $this->request( 'PATCH', $this->user_id, 'subkey', $super_admin_id, [ 'name' => 'Renamed' ] );
		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 'Renamed', Credential_Store::get( $this->user_id, 'subkey' )['name'] );

		$response = $this->request( 'DELETE', $this->user_id, 'subkey', $super_admin_id );
		$this->assertSame( 200, $response->get_status() );
		$this->assertNull( Credential_Store::get( $this->user_id, 'subkey' ) );
	}

	public function test_subsite_administrator_cannot_manage_a_super_admins_passkeys() {
		$super_admin_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		grant_super_admin( $super_admin_id );
		$admin_id = self::factory()->user->create();
		add_user_to_blog( $this->subsite_id, $admin_id, 'administrator' );
		$this->add_credential( $super_admin_id, 'superkey' );
		switch_to_blog( $this->subsite_id );

		$this->assertFalse( is_super_admin( $admin_id ) );
		foreach ( [ [ 'PATCH', [ 'name' => 'Hijacked' ] ], [ 'DELETE', [] ] ] as list( $method, $params ) ) {
			$response = $this->request( $method, $super_admin_id, 'superkey', $admin_id, $params );
			$this->assertSame( 403, $response->get_status(), $method );
			$this->assertSame( 'rest_forbidden', $response->get_data()['code'] );
		}
		$this->assertSame( 'Key superkey', Credential_Store::get( $super_admin_id, 'superkey' )['name'] );
	}
}
