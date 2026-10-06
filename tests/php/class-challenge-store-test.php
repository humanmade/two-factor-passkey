<?php
/**
 * Challenge store tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Challenge_Store;
use InvalidArgumentException;
use WP_UnitTestCase;

/**
 * Tests for Challenge_Store.
 */
class Challenge_Store_Test extends WP_UnitTestCase {

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

	public function test_save_then_consume_returns_binary_challenge() {
		$challenge = random_bytes( 32 );

		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, $challenge );

		$this->assertSame( $challenge, Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_second_consume_returns_null() {
		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, random_bytes( 32 ) );

		$this->assertNotNull( Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_consume_without_save_returns_null() {
		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::GET ) );
	}

	public function test_expired_challenge_returns_null() {
		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, random_bytes( 32 ) );

		$key = Challenge_Store::META_KEY_PREFIX . Challenge_Store::CREATE;
		$stored = get_user_meta( $this->user_id, $key, true );
		$stored['expires'] = time() - 1;
		update_user_meta( $this->user_id, $key, $stored );

		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_ttl_filter_sets_expiry() {
		add_filter(
			'two_factor_passkey_challenge_ttl',
			function () {
				return 600;
			}
		);

		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, random_bytes( 32 ) );

		$stored = get_user_meta( $this->user_id, Challenge_Store::META_KEY_PREFIX . Challenge_Store::CREATE, true );
		$this->assertEqualsWithDelta( time() + 600, $stored['expires'], 5 );
	}

	public function test_challenge_for_another_rp_id_returns_null() {
		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, random_bytes( 32 ) );

		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'other.example.org';
			}
		);

		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_nonce_binding_accepts_the_right_nonce() {
		$challenge = random_bytes( 32 );
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, $challenge, 'nonce-1' );

		$this->assertSame( $challenge, Challenge_Store::consume( $this->user_id, Challenge_Store::GET, 'nonce-1' ) );
	}

	public function test_nonce_binding_rejects_a_wrong_nonce() {
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, random_bytes( 32 ), 'nonce-1' );

		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::GET, 'nonce-2' ) );
	}

	public function test_nonce_binding_rejects_an_empty_nonce() {
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, random_bytes( 32 ), 'nonce-1' );

		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::GET ) );
	}

	public function test_a_failed_consume_still_deletes_the_challenge() {
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, random_bytes( 32 ), 'nonce-1' );

		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::GET, 'nonce-2' ) );
		$this->assertNull( Challenge_Store::consume( $this->user_id, Challenge_Store::GET, 'nonce-1' ) );
	}

	public function test_unknown_ceremony_throws_on_save() {
		$this->expectException( InvalidArgumentException::class );

		Challenge_Store::save( $this->user_id, 'other', random_bytes( 32 ) );
	}

	public function test_unknown_ceremony_throws_on_consume() {
		$this->expectException( InvalidArgumentException::class );

		Challenge_Store::consume( $this->user_id, 'other' );
	}

	public function test_create_and_get_keys_do_not_collide() {
		$create = random_bytes( 32 );
		$get = random_bytes( 32 );

		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, $create );
		Challenge_Store::save( $this->user_id, Challenge_Store::GET, $get );

		$this->assertSame( $get, Challenge_Store::consume( $this->user_id, Challenge_Store::GET ) );
		$this->assertSame( $create, Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_save_replaces_a_pending_challenge() {
		$first = random_bytes( 32 );
		$second = random_bytes( 32 );

		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, $first );
		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, $second );

		$this->assertSame( $second, Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}

	public function test_challenge_is_not_visible_to_another_user() {
		$other_id = self::factory()->user->create();
		$challenge = random_bytes( 32 );

		Challenge_Store::save( $this->user_id, Challenge_Store::CREATE, $challenge );

		$this->assertNull( Challenge_Store::consume( $other_id, Challenge_Store::CREATE ) );
		$this->assertSame( $challenge, Challenge_Store::consume( $this->user_id, Challenge_Store::CREATE ) );
	}
}
