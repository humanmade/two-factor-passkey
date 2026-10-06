<?php
/**
 * Provider tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Credential_Store;
use Two_Factor_Core;
use Two_Factor_Passkey;
use Two_Factor_Provider;
use WP_UnitTestCase;

/**
 * Tests for the Two_Factor_Passkey provider and plugin functions.
 */
class Provider_Test extends WP_UnitTestCase {

	use Site_Url;

	/**
	 * User ID.
	 *
	 * @var int
	 */
	private $user_id;

	/**
	 * User.
	 *
	 * @var \WP_User
	 */
	private $user;

	/**
	 * Provider.
	 *
	 * @var Two_Factor_Passkey
	 */
	private $provider;

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$this->user_id = self::factory()->user->create();
		$this->user = get_user_by( 'id', $this->user_id );
		$_POST = [];

		$this->provider = Two_Factor_Passkey::get_instance();
	}

	/**
	 * Register an authenticator for the test user.
	 *
	 * @param Soft_Authenticator $authenticator Authenticator.
	 */
	private function register( Soft_Authenticator $authenticator ) {
		$options = Ceremony::get_creation_options( $this->user );
		$this->assertIsArray( Ceremony::verify_registration( $this->user, $authenticator->create( $options ) ) );
	}

	/**
	 * Post a login response the way WordPress would receive it.
	 *
	 * @param Soft_Authenticator $authenticator Authenticator.
	 * @param array              $overrides     Response overrides.
	 */
	private function post_login( Soft_Authenticator $authenticator, array $overrides = [] ) {
		$nonce = Two_Factor_Core::create_login_nonce( $this->user_id )['key'];
		$options = Ceremony::get_request_options( $this->user );
		$this->assertIsArray( $options );

		$_POST['wp-auth-nonce'] = wp_slash( $nonce );
		$_POST[ Two_Factor_Passkey::RESPONSE_FIELD ] = wp_slash( $authenticator->get( $options, $overrides ) );
	}

	public function test_provider_is_registered_with_two_factor() {
		$providers = Two_Factor_Core::get_providers();

		$this->assertArrayHasKey( 'Two_Factor_Passkey', $providers );
		$this->assertInstanceOf( Two_Factor_Passkey::class, $providers['Two_Factor_Passkey'] );
		$this->assertInstanceOf( Two_Factor_Provider::class, $providers['Two_Factor_Passkey'] );
	}

	public function test_is_available_for_user() {
		$this->assertFalse( $this->provider->is_available_for_user( $this->user ) );

		$this->register( new Soft_Authenticator() );

		$this->assertTrue( $this->provider->is_available_for_user( $this->user ) );
	}

	public function test_availability_does_not_depend_on_flags() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );

		Credential_Store::update( $this->user_id, $authenticator->get_id(), [ 'flagged_at' => time() ] );

		$this->assertTrue( $this->provider->is_available_for_user( $this->user ) );
	}

	public function test_availability_does_not_depend_on_rp_id() {
		$this->register( new Soft_Authenticator() );
		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'other.example.org';
			}
		);

		$this->assertTrue( $this->provider->is_available_for_user( $this->user ) );
	}

	public function test_availability_does_not_depend_on_https() {
		$this->register( new Soft_Authenticator() );
		$this->set_site_url( 'http://example.org' );

		$this->assertTrue( $this->provider->is_available_for_user( $this->user ) );
	}

	public function test_validate_authentication_accepts_a_valid_response() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );
		$this->post_login( $authenticator );

		$this->assertTrue( $this->provider->validate_authentication( $this->user ) );
	}

	public function test_validate_authentication_rejects_an_invalid_response() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );
		$this->post_login( $authenticator, [ 'corrupt_signature' => true ] );

		$this->assertFalse( $this->provider->validate_authentication( $this->user ) );
	}

	public function test_validate_authentication_rejects_a_missing_response() {
		$this->register( new Soft_Authenticator() );

		$this->assertFalse( $this->provider->validate_authentication( $this->user ) );
	}

	public function test_validate_authentication_rejects_another_login_nonce() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );
		$this->post_login( $authenticator );
		$_POST['wp-auth-nonce'] = wp_slash( 'wrong-nonce' );

		$this->assertFalse( $this->provider->validate_authentication( $this->user ) );
	}

	public function test_authentication_page_prints_options_when_keys_are_usable() {
		$this->register( new Soft_Authenticator() );
		Two_Factor_Core::create_login_nonce( $this->user_id );

		ob_start();
		$this->provider->authentication_page( $this->user );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'name="two_factor_passkey_response"', $output );
		$this->assertStringContainsString( 'data-options="', $output );
	}

	public function test_authentication_page_prints_no_options_when_no_key_is_usable() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );
		Credential_Store::update( $this->user_id, $authenticator->get_id(), [ 'flagged_at' => time() ] );
		Two_Factor_Core::create_login_nonce( $this->user_id );

		ob_start();
		$this->provider->authentication_page( $this->user );
		$output = ob_get_clean();

		$this->assertStringNotContainsString( 'data-options', $output );
		$this->assertStringNotContainsString( 'name="two_factor_passkey_response"', $output );
		$this->assertStringContainsString( 'two-factor-passkey-error', $output );
	}

	public function test_enable_provider_for_user_adds_the_key_once() {
		\HM\Two_Factor_Passkey\enable_provider_for_user( $this->user_id );
		\HM\Two_Factor_Passkey\enable_provider_for_user( $this->user_id );

		$this->assertSame( [ \HM\Two_Factor_Passkey\PROVIDER_KEY ], get_user_meta( $this->user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true ) );
	}

	public function test_enable_provider_for_user_keeps_existing_providers() {
		update_user_meta( $this->user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, [ 'Two_Factor_Email' ] );

		\HM\Two_Factor_Passkey\enable_provider_for_user( $this->user_id );

		$this->assertSame(
			[ 'Two_Factor_Email', \HM\Two_Factor_Passkey\PROVIDER_KEY ],
			get_user_meta( $this->user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true )
		);
	}

	public function test_register_provider_adds_the_class_file_path() {
		$providers = \HM\Two_Factor_Passkey\register_provider( [ 'Two_Factor_Email' => '/path/to/email.php' ] );

		$this->assertSame( '/path/to/email.php', $providers['Two_Factor_Email'] );
		$this->assertSame( 'Two_Factor_Passkey', \HM\Two_Factor_Passkey\PROVIDER_KEY );
		$this->assertFileExists( $providers[ \HM\Two_Factor_Passkey\PROVIDER_KEY ] );
		$this->assertStringEndsWith( '/inc/class-two-factor-passkey.php', $providers[ \HM\Two_Factor_Passkey\PROVIDER_KEY ] );
	}
}
