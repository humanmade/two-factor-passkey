<?php
/**
 * Passkey provider for the Two Factor plugin.
 *
 * Two Factor uses the class name as the provider key, so this class is global.
 *
 * @package HM\Two_Factor_Passkey
 */

use HM\Two_Factor_Passkey\Ceremony;
use HM\Two_Factor_Passkey\Credential_Store;
use HM\Two_Factor_Passkey\Profile_UI;

/**
 * Passkey (WebAuthn) second factor.
 */
class Two_Factor_Passkey extends Two_Factor_Provider {

	/**
	 * Form field holding the JSON response from navigator.credentials.get().
	 */
	const RESPONSE_FIELD = 'two_factor_passkey_response';

	/**
	 * Error from the last failed validation in this request, shown when the
	 * login step is printed again.
	 *
	 * @var WP_Error|null
	 */
	protected $last_error = null;

	/**
	 * Get the single instance.
	 *
	 * @return self
	 */
	public static function get_instance() {
		static $instance;

		if ( ! isset( $instance ) ) {
			$instance = new self();
		}

		return $instance;
	}

	/**
	 * Hook the passkey settings into the Two Factor options table.
	 */
	protected function __construct() {
		add_action( 'two-factor-user-options-' . __CLASS__, [ Profile_UI::class, 'render' ] );
		parent::__construct();
	}

	/**
	 * Get the provider name.
	 *
	 * @return string
	 */
	public function get_label() {
		return _x( 'Passkey or security key', 'two-factor provider name', 'two-factor-passkey' );
	}

	/**
	 * Print the passkey step of the login form.
	 *
	 * @param WP_User $user User signing in.
	 */
	public function authentication_page( $user ) {
		$options = Ceremony::get_request_options( $user );
		$error = is_wp_error( $options ) ? $options : $this->last_error;

		if ( $error ) {
			printf( '<p class="two-factor-passkey-error">%s</p>', esc_html( $error->get_error_message() ) );
		}

		if ( is_wp_error( $options ) ) {
			return;
		}

		wp_enqueue_script( 'two-factor-passkey-login' );
		?>
		<div class="two-factor-passkey-login" data-options="<?php echo esc_attr( wp_json_encode( $options ) ); ?>">
			<p><?php esc_html_e( 'Use your passkey or security key to finish signing in.', 'two-factor-passkey' ); ?></p>
			<p class="two-factor-passkey-unsupported" hidden><?php esc_html_e( 'This browser cannot use passkeys. Use another method below.', 'two-factor-passkey' ); ?></p>
			<p>
				<button type="button" class="button button-primary button-large two-factor-passkey-start"><?php esc_html_e( 'Use passkey', 'two-factor-passkey' ); ?></button>
			</p>
			<p class="two-factor-passkey-status" role="status" aria-live="polite"></p>
			<input type="hidden" name="<?php echo esc_attr( self::RESPONSE_FIELD ); ?>" value="" />
			<noscript><p><?php esc_html_e( 'Passkeys need JavaScript. Turn it on, or use another method.', 'two-factor-passkey' ); ?></p></noscript>
		</div>
		<?php
	}

	/**
	 * Verify the passkey response posted with the login form.
	 *
	 * @param WP_User $user User signing in.
	 * @return bool
	 */
	public function validate_authentication( $user ) {
		// Two Factor checks its login nonce before calling this.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		// The response is JSON that must reach the verifier unchanged; it is parsed strictly and checked cryptographically.
		// phpcs:ignore HM.Security.ValidatedSanitizedInput.InputNotSanitized
		$response = isset( $_POST[ self::RESPONSE_FIELD ] ) ? wp_unslash( (string) $_POST[ self::RESPONSE_FIELD ] ) : '';
		$login_nonce = isset( $_POST['wp-auth-nonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wp-auth-nonce'] ) ) : '';
		// phpcs:enable

		$result = Ceremony::verify_assertion( $user, $response, $login_nonce );
		if ( is_wp_error( $result ) ) {
			$this->last_error = $result;
			return false;
		}

		$this->last_error = null;
		return true;
	}

	/**
	 * Whether the user has set up passkeys.
	 *
	 * This must not depend on the current request (site, scheme, flags): Two
	 * Factor uses it both to decide whether to ask for a second factor and to
	 * tick the profile checkbox. Request checks happen in the login step.
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	public function is_available_for_user( $user ) {
		return Credential_Store::has_any( $user->ID );
	}
}
