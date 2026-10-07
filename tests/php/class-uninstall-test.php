<?php
/**
 * Uninstall tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Challenge_Store;
use HM\Two_Factor_Passkey\Credential_Store;
use WP_UnitTestCase;

/**
 * Tests for delete_all_data().
 */
class Uninstall_Test extends WP_UnitTestCase {

	use Site_Url;

	/**
	 * Unrelated meta key that must survive.
	 */
	const OTHER_KEY = 'unrelated_meta';

	/**
	 * Names of the passkey meta keys.
	 *
	 * @return string[]
	 */
	private function passkey_keys(): array {
		return [
			Credential_Store::META_KEY,
			Credential_Store::HANDLE_META_KEY,
			Challenge_Store::META_KEY_PREFIX . Challenge_Store::CREATE,
			Challenge_Store::META_KEY_PREFIX . Challenge_Store::GET,
		];
	}

	/**
	 * Give a user credentials, a user handle, both pending challenges and unrelated meta.
	 *
	 * @param int $user_id User ID.
	 */
	private function add_passkey_data( int $user_id ) {
		Credential_Store::add(
			$user_id,
			[
				'id' => 'key' . $user_id,
				'public_key' => '-----BEGIN PUBLIC KEY-----secret',
				'sign_count' => 0,
				'rp_id' => 'example.org',
				'name' => 'Key',
				'created_at' => time(),
				'last_used_at' => null,
				'flagged_at' => null,
			]
		);
		Credential_Store::get_user_handle( $user_id );
		Challenge_Store::save( $user_id, Challenge_Store::CREATE, random_bytes( 32 ) );
		Challenge_Store::save( $user_id, Challenge_Store::GET, random_bytes( 32 ), 'login-nonce' );
		update_user_meta( $user_id, self::OTHER_KEY, 'keep me' );

		foreach ( $this->passkey_keys() as $key ) {
			$this->assertNotEmpty( get_user_meta( $user_id, $key, true ), $key );
		}
	}

	public function test_delete_all_data_removes_passkey_meta_and_keeps_other_meta() {
		$this->set_site_url( 'https://example.org' );
		$user_ids = [ self::factory()->user->create(), self::factory()->user->create() ];
		foreach ( $user_ids as $user_id ) {
			$this->add_passkey_data( $user_id );
		}

		\HM\Two_Factor_Passkey\delete_all_data();

		global $wpdb;
		foreach ( $user_ids as $user_id ) {
			foreach ( $this->passkey_keys() as $key ) {
				$this->assertSame( [], get_user_meta( $user_id, $key ), $key );
				$this->assertSame( '', get_user_meta( $user_id, $key, true ), $key );
			}
			$this->assertSame( 'keep me', get_user_meta( $user_id, self::OTHER_KEY, true ) );
			$this->assertFalse( Credential_Store::has_any( $user_id ) );
		}

		$in = implode( ',', array_map( 'intval', $user_ids ) );
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key LIKE '\\_two\\_factor\\_passkey\\_%' AND user_id IN ({$in})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$this->assertSame( 0, $count );
	}
}
