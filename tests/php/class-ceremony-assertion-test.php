<?php
/**
 * Authentication ceremony tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Base64url;
use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Credential_Store;
use Two_Factor_Core;
use WP_UnitTestCase;
use WP_User;

/**
 * Tests for Ceremony::get_request_options() and Ceremony::verify_assertion().
 */
class Ceremony_Assertion_Test extends WP_UnitTestCase {

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
	 * @var WP_User
	 */
	private $user;

	/**
	 * Authenticator registered for the user.
	 *
	 * @var Soft_Authenticator
	 */
	private $authenticator;

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$this->user_id = self::factory()->user->create();
		$this->user = get_user_by( 'id', $this->user_id );
		$_POST = [];

		$this->authenticator = new Soft_Authenticator();
		$this->register( $this->user, $this->authenticator );
	}

	/**
	 * Register an authenticator for a user.
	 *
	 * @param WP_User            $user          User.
	 * @param Soft_Authenticator $authenticator Authenticator.
	 */
	private function register( WP_User $user, Soft_Authenticator $authenticator ) {
		$options = Ceremony::get_creation_options( $user );
		$result = Ceremony::verify_registration( $user, $authenticator->create( $options ) );
		$this->assertIsArray( $result );
	}

	/**
	 * Create a login nonce and request options.
	 *
	 * @param WP_User|null $user User, defaults to the test user.
	 * @return array{0: array|\WP_Error, 1: string} Options and the login nonce.
	 */
	private function begin_login( ?WP_User $user = null ): array {
		$user = $user ?? $this->user;
		$nonce = Two_Factor_Core::create_login_nonce( $user->ID )['key'];

		return [ Ceremony::get_request_options( $user ), $nonce ];
	}

	/**
	 * Run a full login with the test authenticator.
	 *
	 * @param array              $overrides     Response overrides.
	 * @param Soft_Authenticator $authenticator Authenticator, defaults to the registered one.
	 * @return array|\WP_Error
	 */
	private function login( array $overrides = [], ?Soft_Authenticator $authenticator = null ) {
		$authenticator = $authenticator ?? $this->authenticator;
		list( $options, $nonce ) = $this->begin_login();
		$this->assertIsArray( $options );

		return Ceremony::verify_assertion( $this->user, $authenticator->get( $options, $overrides ), $nonce );
	}

	/**
	 * Assert a WP_Error with a code.
	 *
	 * @param string $code   Code without the prefix.
	 * @param mixed  $result Result to check.
	 */
	private function assert_error( string $code, $result ) {
		$this->assertWPError( $result );
		$this->assertSame( 'two_factor_passkey_' . $code, $result->get_error_code() );
	}

	public function test_successful_login_updates_the_credential() {
		$result = $this->login();

		$this->assertIsArray( $result );
		$stored = Credential_Store::get( $this->user_id, $this->authenticator->get_id() );
		$this->assertSame( 1, $stored['sign_count'] );
		$this->assertEqualsWithDelta( time(), $stored['last_used_at'], 5 );
		$this->assertNull( $stored['flagged_at'] );
		$this->assertSame( $stored['sign_count'], $result['sign_count'] );

		$this->assertIsArray( $this->login() );
		$this->assertSame( 2, Credential_Store::get( $this->user_id, $this->authenticator->get_id() )['sign_count'] );
	}

	public function test_request_options_shape() {
		list( $options ) = $this->begin_login();

		$this->assertSame( 'example.org', $options['rpId'] );
		$this->assertSame( 'preferred', $options['userVerification'] );
		$this->assertSame( 32, strlen( Base64url::decode( $options['challenge'] ) ) );
	}

	public function test_counter_zero_followed_by_zero_passes() {
		$this->assertSame( 0, Credential_Store::get( $this->user_id, $this->authenticator->get_id() )['sign_count'] );

		$this->assertIsArray( $this->login( [ 'sign_count' => 0 ] ) );
		$this->assertIsArray( $this->login( [ 'sign_count' => 0 ] ) );

		$stored = Credential_Store::get( $this->user_id, $this->authenticator->get_id() );
		$this->assertSame( 0, $stored['sign_count'] );
		$this->assertNull( $stored['flagged_at'] );
	}

	public function test_counter_regression_flags_the_credential() {
		$fired = [];
		add_action(
			'two_factor_passkey_counter_regression',
			function ( $user, $credential ) use ( &$fired ) {
				$fired[] = [ $user->ID, $credential['id'] ];
			},
			10,
			2
		);

		$this->assertIsArray( $this->login( [ 'sign_count' => 5 ] ) );
		$this->assert_error( 'credential_flagged', $this->login( [ 'sign_count' => 3 ] ) );

		$stored = Credential_Store::get( $this->user_id, $this->authenticator->get_id() );
		$this->assertNotEmpty( $stored['flagged_at'] );
		$this->assertSame( 5, $stored['sign_count'] );
		$this->assertSame( [ [ $this->user_id, $this->authenticator->get_id() ] ], $fired );

		// With the only key flagged there is nothing to offer.
		list( $options ) = $this->begin_login();
		$this->assert_error( 'no_usable_credentials', $options );

		// Another key keeps the login step available, but the flagged one stays refused.
		$this->register( $this->user, new Soft_Authenticator() );
		$this->assert_error( 'credential_flagged', $this->login( [ 'sign_count' => 10 ] ) );
		$this->assertCount( 1, $fired );
	}

	public function test_counter_equal_to_stored_value_is_a_regression() {
		$this->assertIsArray( $this->login( [ 'sign_count' => 5 ] ) );

		$this->assert_error( 'credential_flagged', $this->login( [ 'sign_count' => 5 ] ) );
	}

	public function test_no_usable_credentials() {
		$other = get_user_by( 'id', self::factory()->user->create() );

		list( $options ) = $this->begin_login( $other );

		$this->assert_error( 'no_usable_credentials', $options );
	}

	public function test_allow_credentials_contains_only_usable_credentials() {
		$second = new Soft_Authenticator();
		$this->register( $this->user, $second );
		$third = new Soft_Authenticator();
		$this->register( $this->user, $third );
		$fourth = new Soft_Authenticator();
		$this->register( $this->user, $fourth );

		Credential_Store::update( $this->user_id, $second->get_id(), [ 'flagged_at' => time() ] );
		$other_rp = Credential_Store::get( $this->user_id, $third->get_id() );
		$other_rp['id'] = 'b3RoZXJfcnA';
		$other_rp['rp_id'] = 'other.example.org';
		Credential_Store::add( $this->user_id, $other_rp );
		Credential_Store::delete( $this->user_id, $third->get_id() );

		list( $options ) = $this->begin_login();

		$ids = array_column( $options['allowCredentials'], 'id' );
		sort( $ids );
		$expected = [ $this->authenticator->get_id(), $fourth->get_id() ];
		sort( $expected );
		$this->assertSame( $expected, $ids );
	}

	public function test_login_nonce_missing() {
		$result = Ceremony::get_request_options( $this->user );

		$this->assert_error( 'login_nonce_missing', $result );
	}

	public function test_wrong_login_nonce_is_rejected() {
		list( $options ) = $this->begin_login();

		$result = Ceremony::verify_assertion( $this->user, $this->authenticator->get( $options ), 'wrong-nonce' );

		$this->assert_error( 'challenge_invalid', $result );
	}

	public function test_empty_login_nonce_is_rejected() {
		list( $options ) = $this->begin_login();

		$this->assert_error( 'challenge_invalid', Ceremony::verify_assertion( $this->user, $this->authenticator->get( $options ), '' ) );
	}

	public function test_replay_is_rejected() {
		list( $options, $nonce ) = $this->begin_login();
		$response = $this->authenticator->get( $options );

		$this->assertIsArray( Ceremony::verify_assertion( $this->user, $response, $nonce ) );
		$this->assert_error( 'challenge_invalid', Ceremony::verify_assertion( $this->user, $response, $nonce ) );
	}

	public function test_login_without_options_is_rejected() {
		$nonce = Two_Factor_Core::create_login_nonce( $this->user_id )['key'];
		$options = [ 'challenge' => Base64url::encode( random_bytes( 32 ) ) ];

		$this->assert_error( 'challenge_invalid', Ceremony::verify_assertion( $this->user, $this->authenticator->get( $options ), $nonce ) );
	}

	public function test_get_response_against_create_options_fails() {
		$options = Ceremony::get_creation_options( $this->user );

		$result = Ceremony::verify_registration( $this->user, $this->authenticator->get( $options ) );

		$this->assert_error( 'response_invalid', $result );
	}

	public function test_create_response_against_request_options_fails() {
		list( $options, $nonce ) = $this->begin_login();

		$result = Ceremony::verify_assertion( $this->user, $this->authenticator->create( $options ), $nonce );

		$this->assert_error( 'response_invalid', $result );
	}

	public function test_create_type_signed_for_get_options_fails() {
		$this->assert_error( 'verification_failed', $this->login( [ 'type' => 'webauthn.create' ] ) );
	}

	public function test_create_challenge_cannot_be_used_for_login() {
		$create_options = Ceremony::get_creation_options( $this->user );

		$result = $this->login( [ 'challenge' => $create_options['challenge'] ] );

		$this->assert_error( 'verification_failed', $result );
	}

	public function test_another_users_credential_is_unknown() {
		$other = get_user_by( 'id', self::factory()->user->create() );
		$other_authenticator = new Soft_Authenticator();
		$this->register( $other, $other_authenticator );

		$this->assert_error( 'credential_unknown', $this->login( [], $other_authenticator ) );
	}

	public function test_unknown_credential_id_is_rejected() {
		$result = $this->login( [ 'credential_id' => random_bytes( 20 ) ] );

		$this->assert_error( 'credential_unknown', $result );
	}

	public function test_wrong_user_handle_is_rejected() {
		$result = $this->login( [ 'user_handle' => random_bytes( 32 ) ] );

		$this->assert_error( 'user_handle_mismatch', $result );
	}

	public function test_another_users_handle_is_rejected() {
		$other_id = self::factory()->user->create();

		$result = $this->login( [ 'user_handle' => Credential_Store::get_user_handle( $other_id ) ] );

		$this->assert_error( 'user_handle_mismatch', $result );
	}

	public function test_correct_user_handle_passes() {
		$result = $this->login( [ 'user_handle' => Credential_Store::get_user_handle( $this->user_id ) ] );

		$this->assertIsArray( $result );
	}

	public function test_wrong_origin_is_rejected() {
		foreach ( [ 'https://evilexample.org', 'https://example.org.evil.com', 'http://example.org' ] as $origin ) {
			$this->assert_error( 'origin_invalid', $this->login( [ 'origin' => $origin ] ) );
		}
	}

	public function test_cross_origin_is_rejected() {
		$this->assert_error( 'origin_invalid', $this->login( [ 'cross_origin' => true ] ) );
	}

	public function test_corrupted_signature_is_rejected() {
		$this->assert_error( 'verification_failed', $this->login( [ 'corrupt_signature' => true ] ) );

		$stored = Credential_Store::get( $this->user_id, $this->authenticator->get_id() );
		$this->assertNull( $stored['last_used_at'] );
		$this->assertSame( 0, $stored['sign_count'] );
	}

	public function test_wrong_rp_id_hash_is_rejected() {
		$this->assert_error( 'verification_failed', $this->login( [ 'rp_id' => 'evil.example' ] ) );
	}

	public function test_wrong_type_is_rejected() {
		$this->assert_error( 'verification_failed', $this->login( [ 'type' => 'webauthn.create' ] ) );
	}

	public function test_wrong_challenge_is_rejected() {
		$result = $this->login( [ 'challenge' => Base64url::encode( random_bytes( 32 ) ) ] );

		$this->assert_error( 'verification_failed', $result );
	}

	public function test_missing_user_presence_is_rejected() {
		$this->assert_error( 'verification_failed', $this->login( [ 'flags' => 0x04 ] ) );
	}

	public function test_missing_user_verification_is_rejected_when_required() {
		add_filter( 'two_factor_passkey_require_user_verification', '__return_true' );

		$this->assert_error( 'verification_failed', $this->login( [ 'flags' => 0x01 ] ) );
		$this->assertIsArray( $this->login() );
	}

	public function test_credential_from_another_rp_id_is_not_usable() {
		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'other.example.org';
			}
		);

		list( $options ) = $this->begin_login();

		$this->assert_error( 'no_usable_credentials', $options );
	}

	public function test_credential_from_another_rp_id_is_unknown_when_verifying() {
		list( $options, $nonce ) = $this->begin_login();
		$response = $this->authenticator->get( $options );

		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'other.example.org';
			}
		);

		// The challenge was stored for example.org, so it no longer matches.
		$this->assert_error( 'challenge_invalid', Ceremony::verify_assertion( $this->user, $response, $nonce ) );
	}

	public function test_insecure_context() {
		$this->set_site_url( 'http://example.org' );

		list( $options ) = $this->begin_login();

		$this->assert_error( 'insecure_context', $options );
	}

	public function test_garbage_response_is_rejected() {
		list( , $nonce ) = $this->begin_login();

		$this->assert_error( 'response_invalid', Ceremony::verify_assertion( $this->user, 'not json', $nonce ) );
	}
}
