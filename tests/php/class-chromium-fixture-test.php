<?php
/**
 * Tests against a ceremony recorded from Chromium's virtual authenticator.
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
 * Replays the fixture written by tests/e2e/capture-fixture.spec.ts.
 */
class Chromium_Fixture_Test extends WP_UnitTestCase {

	use Site_Url;

	const NONCE = 'fixture-nonce';

	/**
	 * Recorded ceremony.
	 *
	 * @var array
	 */
	private $fixture;

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

	public function set_up() {
		parent::set_up();

		$this->fixture = json_decode( (string) file_get_contents( __DIR__ . '/fixtures/chromium-virtual-authenticator.json' ), true );
		$this->set_site_url( $this->fixture['origin'] );

		$this->user_id = self::factory()->user->create();
		$this->user = get_user_by( 'id', $this->user_id );
		update_user_meta( $this->user_id, Credential_Store::HANDLE_META_KEY, $this->fixture['user_handle'] );
	}

	/**
	 * Run the recorded registration, optionally with another response.
	 *
	 * @param array|null $response Registration response, defaults to the recorded one.
	 * @return array|\WP_Error
	 */
	private function register( ?array $response = null ) {
		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, Base64url::decode( $this->fixture['creation_options']['challenge'] ) );

		return Ceremony::verify_registration( $this->user, wp_json_encode( $response ?? $this->fixture['registration_response'] ), 'Fixture' );
	}

	/**
	 * Run the recorded assertion, optionally with another response.
	 *
	 * @param array|null $response Assertion response, defaults to the recorded one.
	 * @return array|\WP_Error
	 */
	private function authenticate( ?array $response = null ) {
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, Base64url::decode( $this->fixture['request_options']['challenge'] ), self::NONCE );

		return Ceremony::verify_assertion( $this->user, wp_json_encode( $response ?? $this->fixture['assertion_response'] ), self::NONCE );
	}

	public function test_recorded_registration_verifies() {
		$this->assertNotWPError( $this->register() );
		$this->assertCount( 1, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_recorded_assertion_verifies() {
		$this->assertNotWPError( $this->register() );
		$this->assertNotWPError( $this->authenticate() );
	}

	public function test_changed_origin_fails() {
		$this->assertNotWPError( $this->register() );

		$response = $this->fixture['assertion_response'];
		$client_data = Base64url::decode( $response['response']['clientDataJSON'] );
		$altered = str_replace( $this->fixture['origin'], substr_replace( $this->fixture['origin'], 'x', -1 ), $client_data );
		$this->assertNotSame( $client_data, $altered );
		$response['response']['clientDataJSON'] = Base64url::encode( $altered );

		$this->assertWPError( $this->authenticate( $response ) );
	}

	public function test_replayed_assertion_fails() {
		$this->assertNotWPError( $this->register() );
		$this->assertNotWPError( $this->authenticate() );

		$replay = Ceremony::verify_assertion( $this->user, wp_json_encode( $this->fixture['assertion_response'] ), self::NONCE );
		$this->assertWPError( $replay );
	}

	public function test_registration_for_another_rp_id_fails() {
		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'example.org';
			}
		);

		$this->assertWPError( $this->register() );
	}
}
