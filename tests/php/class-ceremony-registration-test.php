<?php
/**
 * Registration ceremony tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Base64url;
use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Challenge_Store;
use HM\Two_Factor_Passkey\Credential_Store;
use WP_UnitTestCase;

/**
 * Tests for Ceremony::get_creation_options() and Ceremony::verify_registration().
 */
class Ceremony_Registration_Test extends WP_UnitTestCase {

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

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$this->user_id = self::factory()->user->create();
		$this->user = get_user_by( 'id', $this->user_id );
		$_POST = [];
	}

	/**
	 * Request options and register with the given authenticator.
	 *
	 * @param Soft_Authenticator $authenticator Authenticator.
	 * @param array              $overrides     Response overrides.
	 * @param string             $name          Passkey name.
	 * @return array|\WP_Error
	 */
	private function register( Soft_Authenticator $authenticator, array $overrides = [], string $name = '' ) {
		$options = Ceremony::get_creation_options( $this->user );
		$this->assertIsArray( $options );

		return Ceremony::verify_registration( $this->user, $authenticator->create( $options, $overrides ), $name );
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

	public function test_registration_stores_the_expected_shape() {
		$authenticator = new Soft_Authenticator();

		$result = $this->register( $authenticator, [], 'Work laptop' );

		$this->assertIsArray( $result );
		$this->assertEqualsCanonicalizing(
			[
				'id',
				'public_key',
				'sign_count',
				'rp_id',
				'name',
				'aaguid',
				'transports',
				'backup_eligible',
				'backed_up',
				'user_verified',
				'created_at',
				'last_used_at',
				'flagged_at',
			],
			array_keys( $result )
		);
		$this->assertSame( $authenticator->get_id(), $result['id'] );
		$this->assertStringStartsWith( '-----BEGIN PUBLIC KEY-----', $result['public_key'] );
		$this->assertSame( 0, $result['sign_count'] );
		$this->assertSame( 'example.org', $result['rp_id'] );
		$this->assertSame( 'Work laptop', $result['name'] );
		$this->assertSame( '00000000-0000-0000-0000-000000000000', $result['aaguid'] );
		$this->assertSame( [ 'internal' ], $result['transports'] );
		$this->assertFalse( $result['backup_eligible'] );
		$this->assertFalse( $result['backed_up'] );
		$this->assertTrue( $result['user_verified'] );
		$this->assertEqualsWithDelta( time(), $result['created_at'], 5 );
		$this->assertNull( $result['last_used_at'] );
		$this->assertNull( $result['flagged_at'] );

		$this->assertSame( $result, Credential_Store::get( $this->user_id, $authenticator->get_id() ) );
	}

	public function test_creation_options() {
		$options = Ceremony::get_creation_options( $this->user );

		$this->assertIsArray( $options );
		$this->assertSame( 'none', $options['attestation'] );
		$this->assertSame( 'discouraged', $options['authenticatorSelection']['residentKey'] );
		$this->assertSame( 'preferred', $options['authenticatorSelection']['userVerification'] );
		$this->assertSame( 'example.org', $options['rp']['id'] );
		$this->assertArrayNotHasKey( 'extensions', $options );

		$handle = Base64url::decode( $options['user']['id'] );
		$this->assertSame( 32, strlen( $handle ) );
		$this->assertSame( Credential_Store::get_user_handle( $this->user_id ), $handle );
		$this->assertNotSame( (string) $this->user_id, $handle );
		$this->assertNotSame( (string) $this->user_id, $options['user']['id'] );
		$this->assertSame( $this->user->user_login, $options['user']['name'] );

		$this->assertSame( 32, strlen( Base64url::decode( $options['challenge'] ) ) );
	}

	public function test_exclude_credentials_lists_existing_credentials() {
		$authenticator = new Soft_Authenticator();
		$this->register( $authenticator );

		$options = Ceremony::get_creation_options( $this->user );

		$ids = array_column( $options['excludeCredentials'], 'id' );
		$this->assertSame( [ $authenticator->get_id() ], $ids );
	}

	public function test_user_verification_filter_makes_it_required() {
		add_filter( 'two_factor_passkey_require_user_verification', '__return_true' );

		$options = Ceremony::get_creation_options( $this->user );

		$this->assertSame( 'required', $options['authenticatorSelection']['userVerification'] );
	}

	public function test_insecure_context_returns_an_error() {
		$this->set_site_url( 'http://example.org' );

		$this->assert_error( 'insecure_context', Ceremony::get_creation_options( $this->user ) );
	}

	public function test_limit_reached_when_requesting_options() {
		$this->register( new Soft_Authenticator() );
		add_filter(
			'two_factor_passkey_credential_limit',
			function () {
				return 1;
			}
		);

		$this->assert_error( 'limit_reached', Ceremony::get_creation_options( $this->user ) );
	}

	public function test_limit_reached_when_verifying() {
		$this->register( new Soft_Authenticator() );
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $this->user );
		add_filter(
			'two_factor_passkey_credential_limit',
			function () {
				return 1;
			}
		);

		$this->assert_error( 'limit_reached', Ceremony::verify_registration( $this->user, $authenticator->create( $options ) ) );
		$this->assertCount( 1, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_wrong_origin_is_rejected() {
		foreach ( [ 'https://evilexample.org', 'https://example.org.evil.com', 'http://example.org', 'https://example.org/' ] as $origin ) {
			$this->assert_error( 'origin_invalid', $this->register( new Soft_Authenticator(), [ 'origin' => $origin ] ) );
		}

		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_cross_origin_is_rejected() {
		$this->assert_error( 'origin_invalid', $this->register( new Soft_Authenticator(), [ 'cross_origin' => true ] ) );
	}

	public function test_wrong_rp_id_hash_is_rejected() {
		$this->assert_error( 'verification_failed', $this->register( new Soft_Authenticator(), [ 'rp_id' => 'evil.example' ] ) );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_wrong_type_is_rejected() {
		$this->assert_error( 'verification_failed', $this->register( new Soft_Authenticator(), [ 'type' => 'webauthn.get' ] ) );
	}

	public function test_wrong_challenge_is_rejected() {
		$result = $this->register( new Soft_Authenticator(), [ 'challenge' => Base64url::encode( random_bytes( 32 ) ) ] );

		$this->assert_error( 'verification_failed', $result );
	}

	public function test_replay_is_rejected() {
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $this->user );
		$response = $authenticator->create( $options );

		$this->assertIsArray( Ceremony::verify_registration( $this->user, $response ) );
		$this->assert_error( 'challenge_invalid', Ceremony::verify_registration( $this->user, $response ) );
		$this->assertCount( 1, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_registration_without_options_is_rejected() {
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $this->user );
		Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE );

		$this->assert_error( 'challenge_invalid', Ceremony::verify_registration( $this->user, $authenticator->create( $options ) ) );
	}

	public function test_expired_challenge_is_rejected() {
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $this->user );

		$key = Challenge_Store::META_KEY_PREFIX . Challenge_Store::CREATE;
		$stored = get_user_meta( $this->user_id, $key, true );
		$stored['expires'] = time() - 1;
		update_user_meta( $this->user_id, $key, $stored );

		$this->assert_error( 'challenge_invalid', Ceremony::verify_registration( $this->user, $authenticator->create( $options ) ) );
	}

	public function test_create_challenge_from_another_user_is_rejected() {
		$other = get_user_by( 'id', self::factory()->user->create() );
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $other );

		$this->assert_error( 'challenge_invalid', Ceremony::verify_registration( $this->user, $authenticator->create( $options ) ) );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_duplicate_credential_is_rejected() {
		$authenticator = new Soft_Authenticator();
		$this->assertIsArray( $this->register( $authenticator ) );

		$this->assert_error( 'duplicate', $this->register( $authenticator ) );
		$this->assertCount( 1, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_outer_id_must_match_the_attested_credential_id() {
		$result = $this->register( new Soft_Authenticator(), [ 'id' => Base64url::encode( random_bytes( 20 ) ) ] );

		$this->assert_error( 'response_invalid', $result );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_missing_user_presence_is_rejected() {
		$this->assert_error( 'verification_failed', $this->register( new Soft_Authenticator(), [ 'flags' => 0x44 ] ) );
	}

	public function test_user_verification_is_optional_by_default() {
		$result = $this->register( new Soft_Authenticator(), [ 'flags' => 0x41 ] );

		$this->assertIsArray( $result );
		$this->assertFalse( $result['user_verified'] );
	}

	public function test_missing_user_verification_is_rejected_when_required() {
		add_filter( 'two_factor_passkey_require_user_verification', '__return_true' );

		$this->assert_error( 'verification_failed', $this->register( new Soft_Authenticator(), [ 'flags' => 0x41 ] ) );
		$this->assertIsArray( $this->register( new Soft_Authenticator() ) );
	}

	public function test_garbage_json_is_rejected() {
		Ceremony::get_creation_options( $this->user );

		$this->assert_error( 'response_invalid', Ceremony::verify_registration( $this->user, 'not json' ) );
	}

	public function test_response_missing_fields_is_rejected() {
		Ceremony::get_creation_options( $this->user );

		$response = wp_json_encode(
			[
				'id' => 'YWJj',
				'type' => 'public-key',
				'response' => [ 'clientDataJSON' => 'YWJj' ],
			]
		);

		$this->assert_error( 'response_invalid', Ceremony::verify_registration( $this->user, $response ) );
	}

	public function test_name_is_sanitised() {
		$result = $this->register( new Soft_Authenticator(), [], '<b>My</b> key' );

		$this->assertSame( 'My key', $result['name'] );
	}

	public function test_empty_name_gets_the_default() {
		$first = $this->register( new Soft_Authenticator(), [], '   ' );
		$second = $this->register( new Soft_Authenticator() );

		$this->assertSame( 'Passkey 1', $first['name'] );
		$this->assertSame( 'Passkey 2', $second['name'] );
	}

	public function test_unknown_transports_are_dropped() {
		$authenticator = new Soft_Authenticator();
		$options = Ceremony::get_creation_options( $this->user );
		$response = json_decode( $authenticator->create( $options ), true );
		$response['response']['transports'] = [ 'usb', 'bogus', 7 ];

		$result = Ceremony::verify_registration( $this->user, wp_json_encode( $response ) );

		$this->assertSame( [ 'usb' ], $result['transports'] );
	}
}
