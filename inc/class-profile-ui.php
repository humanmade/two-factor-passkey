<?php
/**
 * Passkey list and controls on the profile and force-2FA screens.
 *
 * @package HM\Two_Factor_Passkey
 */

namespace HM\Two_Factor_Passkey;

use WP_User;

/**
 * Renders the passkey settings inside the Two Factor options table.
 */
class Profile_UI {

	/**
	 * Print the passkey settings for a user.
	 *
	 * @param WP_User $user User whose profile is shown.
	 */
	public static function render( WP_User $user ): void {
		wp_enqueue_script( 'two-factor-passkey-profile' );
		wp_enqueue_style( 'two-factor-passkey-profile' );

		$credentials = Credential_Store::get_all( $user->ID );
		$is_own_account = $user->ID === get_current_user_id();
		?>
		<div class="two-factor-passkey-settings" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-provider-key="<?php echo esc_attr( PROVIDER_KEY ); ?>">
			<table class="two-factor-passkey-table widefat striped" <?php echo $credentials === [] ? 'hidden' : ''; ?>>
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Name', 'two-factor-passkey' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Added', 'two-factor-passkey' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last used', 'two-factor-passkey' ); ?></th>
						<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'two-factor-passkey' ); ?></span></th>
					</tr>
				</thead>
				<tbody>
					<?php
					foreach ( $credentials as $credential ) {
						self::render_row( REST_Controller::prepare_item( $credential ) );
					}
					?>
				</tbody>
			</table>
			<template class="two-factor-passkey-row-template">
				<?php self::render_row( null ); ?>
			</template>

			<p class="two-factor-passkey-empty" <?php echo $credentials === [] ? '' : 'hidden'; ?>>
				<?php esc_html_e( 'No passkeys added yet.', 'two-factor-passkey' ); ?>
			</p>

			<?php if ( ! $is_own_account ) : ?>
				<p class="description"><?php esc_html_e( 'Only the user can add passkeys to their account.', 'two-factor-passkey' ); ?></p>
			<?php elseif ( ! Relying_Party::is_secure_context() ) : ?>
				<p class="description"><?php esc_html_e( 'Passkeys need a secure (HTTPS) connection, so you cannot add one here.', 'two-factor-passkey' ); ?></p>
			<?php else : ?>
				<p class="two-factor-passkey-add-row">
					<label for="two-factor-passkey-new-name"><?php esc_html_e( 'Name for the new passkey (optional)', 'two-factor-passkey' ); ?></label><br />
					<input type="text" id="two-factor-passkey-new-name" class="regular-text two-factor-passkey-new-name" maxlength="<?php echo esc_attr( Credential_Store::NAME_MAX_LENGTH ); ?>" autocomplete="off" />
					<button type="button" class="button two-factor-passkey-add"><?php esc_html_e( 'Add a passkey', 'two-factor-passkey' ); ?></button>
				</p>
			<?php endif; ?>

			<p class="two-factor-passkey-status" role="status" aria-live="polite"></p>
		</div>
		<?php
	}

	/**
	 * Print one passkey row. With no item, prints the empty template row for scripts.
	 *
	 * @param array|null $item Item from REST_Controller::prepare_item().
	 */
	private static function render_row( ?array $item ): void {
		?>
		<tr data-id="<?php echo esc_attr( $item['id'] ?? '' ); ?>">
			<td class="column-name">
				<span class="two-factor-passkey-name"><?php echo esc_html( $item['name'] ?? '' ); ?></span>
				<span class="two-factor-passkey-badge is-flagged" <?php echo empty( $item['flagged'] ) ? 'hidden' : ''; ?>><?php esc_html_e( 'Disabled: may have been copied', 'two-factor-passkey' ); ?></span>
				<span class="two-factor-passkey-badge is-other-site" <?php echo ( $item === null || $item['usable_here'] ) ? 'hidden' : ''; ?>><?php esc_html_e( 'Added on another site', 'two-factor-passkey' ); ?></span>
				<span class="two-factor-passkey-badge is-synced" <?php echo empty( $item['backed_up'] ) ? 'hidden' : ''; ?>><?php esc_html_e( 'Synced', 'two-factor-passkey' ); ?></span>
			</td>
			<td class="column-created"><?php echo esc_html( $item['created_label'] ?? '' ); ?></td>
			<td class="column-last-used"><?php echo esc_html( $item['last_used_label'] ?? '' ); ?></td>
			<td class="column-actions">
				<button type="button" class="button-link two-factor-passkey-rename"><?php esc_html_e( 'Rename', 'two-factor-passkey' ); ?></button>
				|
				<button type="button" class="button-link button-link-delete two-factor-passkey-remove"><?php esc_html_e( 'Remove', 'two-factor-passkey' ); ?></button>
			</td>
		</tr>
		<?php
	}
}
