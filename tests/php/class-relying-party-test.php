<?php
/**
 * Relying party tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Relying_Party;
use WP_UnitTestCase;

/**
 * Tests for Relying_Party.
 */
class Relying_Party_Test extends WP_UnitTestCase {

	use Site_Url;

	public function set_up() {
		parent::set_up();

		$this->set_site_url( 'https://example.org' );
		$_POST = [];
	}

	public function test_id_comes_from_site_url() {
		$this->assertSame( 'example.org', Relying_Party::get_id() );

		$this->set_site_url( 'https://Login.Example.com/wp' );
		$this->assertSame( 'login.example.com', Relying_Party::get_id() );
	}

	public function test_id_filter() {
		add_filter(
			'two_factor_passkey_rp_id',
			function () {
				return 'Example.COM';
			}
		);

		$this->assertSame( 'example.com', Relying_Party::get_id() );
	}

	public function test_allowed_origins_include_site_admin_and_login_origins() {
		add_filter(
			'admin_url',
			function () {
				return 'http://admin.example.org/wp-admin/';
			}
		);
		add_filter(
			'login_url',
			function () {
				return 'https://login.example.org/wp-login.php';
			}
		);

		$origins = Relying_Party::get_allowed_origins();

		$this->assertContains( 'https://example.org', $origins );
		$this->assertContains( 'http://admin.example.org', $origins );
		$this->assertContains( 'https://login.example.org', $origins );
		$this->assertCount( 3, $origins );
	}

	public function test_allowed_origins_are_unique() {
		$this->assertSame( [ 'https://example.org' ], Relying_Party::get_allowed_origins() );
	}

	public function test_non_default_port_is_kept() {
		$this->set_site_url( 'https://example.org:8443' );

		$this->assertSame( [ 'https://example.org:8443' ], Relying_Party::get_allowed_origins() );
		$this->assertTrue( Relying_Party::is_allowed_origin( 'https://example.org:8443' ) );
		$this->assertFalse( Relying_Party::is_allowed_origin( 'https://example.org' ) );
	}

	public function test_default_port_is_dropped() {
		$this->set_site_url( 'https://example.org:443' );
		$this->assertSame( [ 'https://example.org' ], Relying_Party::get_allowed_origins() );

		$this->set_site_url( 'http://example.org:80' );
		$this->assertSame( [ 'http://example.org' ], Relying_Party::get_allowed_origins() );
	}

	public function test_exact_origin_is_allowed() {
		$this->assertTrue( Relying_Party::is_allowed_origin( 'https://example.org' ) );
	}

	public function test_suffix_match_is_not_allowed() {
		$this->assertFalse( Relying_Party::is_allowed_origin( 'https://evilexample.org' ) );
	}

	public function test_prefix_match_is_not_allowed() {
		$this->assertFalse( Relying_Party::is_allowed_origin( 'https://example.org.evil.com' ) );
	}

	public function test_trailing_slash_or_path_is_not_allowed() {
		$this->assertFalse( Relying_Party::is_allowed_origin( 'https://example.org/' ) );
		$this->assertFalse( Relying_Party::is_allowed_origin( 'https://example.org/wp-login.php' ) );
	}

	public function test_other_scheme_is_not_allowed() {
		$this->assertFalse( Relying_Party::is_allowed_origin( 'http://example.org' ) );
	}

	public function test_https_is_a_secure_context() {
		$this->assertTrue( Relying_Party::is_secure_context() );
	}

	public function test_http_is_not_a_secure_context() {
		$this->set_site_url( 'http://example.org' );

		$this->assertFalse( Relying_Party::is_secure_context() );
	}

	public function test_http_localhost_is_a_secure_context() {
		$this->set_site_url( 'http://localhost:8889' );

		$this->assertSame( 'localhost', Relying_Party::get_id() );
		$this->assertTrue( Relying_Party::is_secure_context() );
	}

	public function test_mixed_schemes_are_not_a_secure_context() {
		add_filter(
			'admin_url',
			function () {
				return 'http://example.org/wp-admin/';
			}
		);

		$this->assertFalse( Relying_Party::is_secure_context() );
	}
}
