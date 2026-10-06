<?php
/**
 * Credential store tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Base64url;
use HM\Two_Factor_Passkey\Credential_Store;
use WP_UnitTestCase;

/**
 * Tests for Credential_Store.
 */
class Credential_Store_Test extends WP_UnitTestCase {

	use Site_Url;

	/**
	 * User ID.
	 *
	 * @var int
	 */
	private $user_id;

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$this->user_id = self::factory()->user->create();
		$_POST = [];
	}

	/**
	 * Build a credential record.
	 *
	 * @param string $id        Credential ID.
	 * @param array  $overrides Field overrides.
	 * @return array
	 */
	private function credential( string $id, array $overrides = [] ): array {
		return array_merge(
			[
				'id' => $id,
				'public_key' => "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n",
				'sign_count' => 0,
				'rp_id' => 'example.org',
				'name' => 'Key ' . $id,
				'aaguid' => '00000000-0000-0000-0000-000000000000',
				'transports' => [ 'internal' ],
				'backup_eligible' => false,
				'backed_up' => false,
				'user_verified' => true,
				'created_at' => 1759750000,
				'last_used_at' => null,
				'flagged_at' => null,
			],
			$overrides
		);
	}

	public function test_add_get_and_get_all() {
		$one = $this->credential( 'one' );
		$two = $this->credential( 'two' );

		$this->assertTrue( Credential_Store::add( $this->user_id, $one ) );
		$this->assertTrue( Credential_Store::add( $this->user_id, $two ) );

		$this->assertSame( $one, Credential_Store::get( $this->user_id, 'one' ) );
		$this->assertSame(
			[
				'one' => $one,
				'two' => $two,
			],
			Credential_Store::get_all( $this->user_id )
		);
		$this->assertNull( Credential_Store::get( $this->user_id, 'missing' ) );
		$this->assertTrue( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_no_credentials() {
		$this->assertSame( [], Credential_Store::get_all( $this->user_id ) );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_duplicate_add_returns_false() {
		$this->assertTrue( Credential_Store::add( $this->user_id, $this->credential( 'one' ) ) );
		$this->assertFalse( Credential_Store::add( $this->user_id, $this->credential( 'one', [ 'name' => 'Other' ] ) ) );

		$this->assertSame( 'Key one', Credential_Store::get( $this->user_id, 'one' )['name'] );
		$this->assertCount( 1, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_update_changes_mutable_fields() {
		Credential_Store::add( $this->user_id, $this->credential( 'one' ) );

		$this->assertTrue(
			Credential_Store::update(
				$this->user_id,
				'one',
				[
					'name' => 'Renamed',
					'sign_count' => 7,
					'last_used_at' => 1759760000,
					'flagged_at' => 1759770000,
					'backed_up' => true,
				]
			)
		);

		$credential = Credential_Store::get( $this->user_id, 'one' );
		$this->assertSame( 'Renamed', $credential['name'] );
		$this->assertSame( 7, $credential['sign_count'] );
		$this->assertSame( 1759760000, $credential['last_used_at'] );
		$this->assertSame( 1759770000, $credential['flagged_at'] );
		$this->assertTrue( $credential['backed_up'] );
	}

	public function test_update_ignores_immutable_fields() {
		$original = $this->credential( 'one' );
		Credential_Store::add( $this->user_id, $original );

		$this->assertTrue(
			Credential_Store::update(
				$this->user_id,
				'one',
				[
					'public_key' => 'attacker key',
					'rp_id' => 'evil.example',
					'id' => 'other',
					'created_at' => 1,
					'name' => 'New name',
				]
			)
		);

		$credential = Credential_Store::get( $this->user_id, 'one' );
		$this->assertSame( $original['public_key'], $credential['public_key'] );
		$this->assertSame( 'example.org', $credential['rp_id'] );
		$this->assertSame( 'one', $credential['id'] );
		$this->assertSame( 1759750000, $credential['created_at'] );
		$this->assertSame( 'New name', $credential['name'] );
	}

	public function test_mutable_fields_constant() {
		$this->assertSame( [ 'name', 'sign_count', 'last_used_at', 'flagged_at', 'backed_up' ], Credential_Store::MUTABLE_FIELDS );
	}

	public function test_update_unknown_credential_returns_false() {
		$this->assertFalse( Credential_Store::update( $this->user_id, 'missing', [ 'name' => 'x' ] ) );
	}

	public function test_delete() {
		Credential_Store::add( $this->user_id, $this->credential( 'one' ) );
		Credential_Store::add( $this->user_id, $this->credential( 'two' ) );

		$this->assertTrue( Credential_Store::delete( $this->user_id, 'one' ) );
		$this->assertNull( Credential_Store::get( $this->user_id, 'one' ) );
		$this->assertNotNull( Credential_Store::get( $this->user_id, 'two' ) );
		$this->assertFalse( Credential_Store::delete( $this->user_id, 'one' ) );
	}

	public function test_deleting_the_last_credential_removes_the_meta_row() {
		Credential_Store::add( $this->user_id, $this->credential( 'one' ) );
		$this->assertTrue( metadata_exists( 'user', $this->user_id, Credential_Store::META_KEY ) );

		$this->assertTrue( Credential_Store::delete( $this->user_id, 'one' ) );

		$this->assertFalse( metadata_exists( 'user', $this->user_id, Credential_Store::META_KEY ) );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_get_usable_excludes_flagged_and_other_rp_id_credentials() {
		Credential_Store::add( $this->user_id, $this->credential( 'good' ) );
		Credential_Store::add( $this->user_id, $this->credential( 'flagged', [ 'flagged_at' => 1759770000 ] ) );
		Credential_Store::add( $this->user_id, $this->credential( 'other', [ 'rp_id' => 'other.example.org' ] ) );

		$this->assertSame( [ 'good' ], array_keys( Credential_Store::get_usable( $this->user_id, 'example.org' ) ) );
		$this->assertSame( [ 'other' ], array_keys( Credential_Store::get_usable( $this->user_id, 'other.example.org' ) ) );
		$this->assertCount( 3, Credential_Store::get_all( $this->user_id ) );
	}

	public function test_malformed_meta_entries_are_ignored() {
		$good = $this->credential( 'good' );
		$no_key = $this->credential( 'no_key' );
		unset( $no_key['public_key'] );
		$no_rp = $this->credential( 'no_rp' );
		unset( $no_rp['rp_id'] );

		update_user_meta(
			$this->user_id,
			Credential_Store::META_KEY,
			[
				'good' => $good,
				'string' => 'not an array',
				'no_key' => $no_key,
				'no_rp' => $no_rp,
				'mismatch' => $this->credential( 'something-else' ),
				'no_id' => [
					'public_key' => 'x',
					'rp_id' => 'example.org',
				],
			]
		);

		$this->assertSame( [ 'good' ], array_keys( Credential_Store::get_all( $this->user_id ) ) );
		$this->assertNull( Credential_Store::get( $this->user_id, 'mismatch' ) );
	}

	public function test_non_array_meta_is_ignored() {
		update_user_meta( $this->user_id, Credential_Store::META_KEY, 'garbage' );

		$this->assertSame( [], Credential_Store::get_all( $this->user_id ) );
		$this->assertFalse( Credential_Store::has_any( $this->user_id ) );
	}

	public function test_user_handle_is_32_bytes_and_stable() {
		$handle = Credential_Store::get_user_handle( $this->user_id );

		$this->assertSame( 32, strlen( $handle ) );
		$this->assertSame( $handle, Credential_Store::get_user_handle( $this->user_id ) );
		$this->assertSame( Base64url::encode( $handle ), get_user_meta( $this->user_id, Credential_Store::HANDLE_META_KEY, true ) );
	}

	public function test_user_handles_differ_between_users() {
		$other_id = self::factory()->user->create();

		$this->assertNotSame( Credential_Store::get_user_handle( $this->user_id ), Credential_Store::get_user_handle( $other_id ) );
	}

	public function test_invalid_stored_user_handle_is_replaced() {
		update_user_meta( $this->user_id, Credential_Store::HANDLE_META_KEY, 'short' );

		$this->assertSame( 32, strlen( Credential_Store::get_user_handle( $this->user_id ) ) );
	}

	public function test_sanitize_name_strips_tags() {
		$this->assertSame( 'Work laptop', Credential_Store::sanitize_name( '  <b>Work</b> laptop ' ) );
	}

	public function test_sanitize_name_cuts_multibyte_names_to_100_characters() {
		$name = Credential_Store::sanitize_name( str_repeat( 'é', 150 ) );

		$this->assertSame( 100, mb_strlen( $name ) );
		$this->assertSame( str_repeat( 'é', 100 ), $name );
	}

	public function test_sanitize_name_of_only_markup_is_empty() {
		$this->assertSame( '', Credential_Store::sanitize_name( '<script>alert(1)</script>' ) );
	}

	public function test_default_name_counts_existing_credentials() {
		$this->assertSame( 'Passkey 1', Credential_Store::get_default_name( $this->user_id ) );

		Credential_Store::add( $this->user_id, $this->credential( 'one' ) );
		$this->assertSame( 'Passkey 2', Credential_Store::get_default_name( $this->user_id ) );
	}

	public function test_limit_filter() {
		$this->assertSame( 20, Credential_Store::get_limit( $this->user_id ) );

		add_filter(
			'two_factor_passkey_credential_limit',
			function () {
				return 3;
			}
		);
		$this->assertSame( 3, Credential_Store::get_limit( $this->user_id ) );
	}
}
