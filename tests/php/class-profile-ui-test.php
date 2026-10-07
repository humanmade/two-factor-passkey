<?php
/**
 * Profile UI tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Credential_Store;
use HM\Two_Factor_Passkey\Profile_UI;
use Two_Factor_Core;
use WP_UnitTestCase;

/**
 * Tests for Profile_UI and the asset registration.
 */
class Profile_UI_Test extends WP_UnitTestCase {

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
		$this->editor_id = self::factory()->user->create( [ 'role' => 'editor' ] );
		\HM\Two_Factor_Passkey\register_assets();
	}

	/**
	 * Capture the settings markup for a user.
	 *
	 * @param int $user_id User whose profile is shown.
	 * @return string
	 */
	private function render( int $user_id ): string {
		ob_start();
		Profile_UI::render( get_user_by( 'id', $user_id ) );
		return ob_get_clean();
	}

	/**
	 * Store a credential directly.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Credential ID.
	 * @param string $name    Name.
	 */
	private function add_credential( int $user_id, string $id, string $name = 'Key' ) {
		Credential_Store::add(
			$user_id,
			[
				'id' => $id,
				'public_key' => '-----BEGIN PUBLIC KEY-----secret',
				'sign_count' => 0,
				'rp_id' => 'example.org',
				'name' => $name,
				'aaguid' => '00000000-0000-0000-0000-000000000000',
				'transports' => [],
				'backup_eligible' => false,
				'backed_up' => false,
				'user_verified' => true,
				'created_at' => time(),
				'last_used_at' => null,
				'flagged_at' => null,
			]
		);
	}

	public function test_own_account_over_https_shows_the_add_controls() {
		wp_set_current_user( $this->admin_id );

		$output = $this->render( $this->admin_id );

		$this->assertStringContainsString( 'two-factor-passkey-add', $output );
		$this->assertStringContainsString( 'two-factor-passkey-new-name', $output );
	}

	public function test_another_users_profile_has_no_add_button() {
		wp_set_current_user( $this->admin_id );

		$output = $this->render( $this->editor_id );

		$this->assertStringNotContainsString( 'two-factor-passkey-add', $output );
		$this->assertStringContainsString( 'class="description"', $output );
	}

	public function test_own_account_over_http_has_no_add_button() {
		$this->set_site_url( 'http://example.org' );
		wp_set_current_user( $this->admin_id );

		$output = $this->render( $this->admin_id );

		$this->assertStringNotContainsString( 'two-factor-passkey-add', $output );
		$this->assertStringContainsString( 'class="description"', $output );
	}

	public function test_rows_match_the_stored_credentials() {
		wp_set_current_user( $this->admin_id );
		$this->add_credential( $this->admin_id, 'first', 'Laptop' );
		$this->add_credential( $this->admin_id, 'second', 'Phone' );
		$this->add_credential( $this->editor_id, 'third', 'Not mine' );

		$output = $this->render( $this->admin_id );

		$this->assertStringContainsString( 'data-id="first"', $output );
		$this->assertStringContainsString( 'data-id="second"', $output );
		$this->assertStringNotContainsString( 'data-id="third"', $output );
		$this->assertStringContainsString( 'Laptop', $output );
		$this->assertStringContainsString( 'Phone', $output );
		$this->assertStringNotContainsString( 'secret', $output );
	}

	public function test_names_are_escaped() {
		wp_set_current_user( $this->admin_id );
		$this->add_credential( $this->admin_id, 'xss', '<script>alert(1)</script>' );

		$output = $this->render( $this->admin_id );

		$this->assertStringNotContainsString( '<script>alert(1)</script>', $output );
		$this->assertStringContainsString( '&lt;script&gt;alert(1)&lt;/script&gt;', $output );
	}

	public function test_row_template_is_present() {
		wp_set_current_user( $this->admin_id );

		$this->assertStringContainsString( '<template class="two-factor-passkey-row-template">', $this->render( $this->admin_id ) );
	}

	public function test_table_is_hidden_only_without_credentials() {
		wp_set_current_user( $this->admin_id );
		$pattern = '/<table class="two-factor-passkey-table[^>]*\bhidden\b/';

		$this->assertMatchesRegularExpression( $pattern, $this->render( $this->admin_id ) );

		$this->add_credential( $this->admin_id, 'first' );

		$this->assertDoesNotMatchRegularExpression( $pattern, $this->render( $this->admin_id ) );
	}

	public function test_render_enqueues_the_profile_assets() {
		wp_set_current_user( $this->admin_id );

		$this->render( $this->admin_id );

		$this->assertTrue( wp_script_is( 'two-factor-passkey-profile', 'enqueued' ) );
		$this->assertTrue( wp_style_is( 'two-factor-passkey-profile', 'enqueued' ) );
	}

	public function test_assets_are_registered_on_init() {
		wp_deregister_script( 'two-factor-passkey-profile' );
		$this->assertFalse( wp_script_is( 'two-factor-passkey-profile', 'registered' ) );

		do_action( 'init' );

		foreach ( [ 'two-factor-passkey-webauthn', 'two-factor-passkey-profile', 'two-factor-passkey-login' ] as $handle ) {
			$this->assertTrue( wp_script_is( $handle, 'registered' ), $handle );
		}
		$this->assertTrue( wp_style_is( 'two-factor-passkey-profile', 'registered' ) );
		$this->assertContains( 'wp-api-fetch', wp_scripts()->registered['two-factor-passkey-profile']->deps );
	}

	public function test_two_factor_action_renders_the_settings() {
		wp_set_current_user( $this->admin_id );
		Two_Factor_Core::get_providers();

		ob_start();
		do_action( 'two-factor-user-options-Two_Factor_Passkey', get_user_by( 'id', $this->admin_id ) ); // phpcs:ignore WordPress.NamingConventions.ValidHookName
		$output = ob_get_clean();

		$this->assertStringContainsString( 'two-factor-passkey-settings', $output );
	}
}
