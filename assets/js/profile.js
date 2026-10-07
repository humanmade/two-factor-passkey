( function () {
	'use strict';

	const { __, sprintf } = wp.i18n;
	const passkeys = window.twoFactorPasskey;

	function init( el ) {
		const base = '/two-factor-passkey/v1/users/' + el.dataset.userId + '/passkeys';
		const status = el.querySelector( '.two-factor-passkey-status' );
		const table = el.querySelector( '.two-factor-passkey-table' );
		const tbody = table.querySelector( 'tbody' );
		const empty = el.querySelector( '.two-factor-passkey-empty' );
		const template = el.querySelector( 'template.two-factor-passkey-row-template' );
		const addButton = el.querySelector( '.two-factor-passkey-add' );
		const nameInput = el.querySelector( '.two-factor-passkey-new-name' );

		function say( message ) {
			status.textContent = message;
			wp.a11y.speak( message );
		}

		function errorMessage( error, fallback ) {
			return error && error.message ? error.message : fallback;
		}

		function rowCount() {
			return tbody.querySelectorAll( 'tr[data-id]' ).length;
		}

		function fillRow( row, item ) {
			row.dataset.id = item.id;
			row.querySelector( '.two-factor-passkey-name' ).textContent = item.name;
			row.querySelector( '.column-created' ).textContent = item.created_label;
			row.querySelector( '.column-last-used' ).textContent = item.last_used_label;
			row.querySelector( '.is-flagged' ).hidden = ! item.flagged;
			row.querySelector( '.is-other-site' ).hidden = !! item.usable_here;
			row.querySelector( '.is-synced' ).hidden = ! item.backed_up;
		}

		function toggleEmpty() {
			const hasRows = rowCount() > 0;
			table.hidden = ! hasRows;
			empty.hidden = hasRows;
		}

		function addRow( item ) {
			const row = template.content.querySelector( 'tr' ).cloneNode( true );
			fillRow( row, item );
			tbody.appendChild( row );
			toggleEmpty();
		}

		async function add() {
			addButton.disabled = true;
			say( __( 'Follow the steps in your browser to create a passkey…', 'two-factor-passkey' ) );

			try {
				const options = await wp.apiFetch( { path: base + '/options', method: 'POST' } );
				const credential = await navigator.credentials.create( { publicKey: passkeys.toCreationOptions( options ) } );
				const item = await wp.apiFetch( {
					path: base,
					method: 'POST',
					data: { credential: passkeys.credentialToJSON( credential ), name: nameInput.value },
				} );

				addRow( item );
				nameInput.value = '';
				say( __( 'Passkey added.', 'two-factor-passkey' ) );

				const checkbox = document.querySelector( 'input[type="checkbox"][name="_two_factor_enabled_providers[]"][value="' + el.dataset.providerKey + '"]' );
				if ( checkbox ) {
					checkbox.checked = true;
				}
			} catch ( error ) {
				if ( error && error.name === 'NotAllowedError' ) {
					say( __( 'Adding the passkey was cancelled or timed out.', 'two-factor-passkey' ) );
				} else if ( error && error.name === 'InvalidStateError' ) {
					say( __( 'This passkey is already registered.', 'two-factor-passkey' ) );
				} else {
					say( errorMessage( error, __( 'The passkey could not be added.', 'two-factor-passkey' ) ) );
				}
			} finally {
				addButton.disabled = false;
			}
		}

		async function rename( row ) {
			const current = row.querySelector( '.two-factor-passkey-name' ).textContent;
			const answer = window.prompt( __( 'New name for this passkey', 'two-factor-passkey' ), current );
			const name = answer === null ? '' : answer.trim();
			if ( ! name ) {
				return;
			}

			try {
				const item = await wp.apiFetch( {
					path: base + '/' + encodeURIComponent( row.dataset.id ),
					method: 'PATCH',
					data: { name: name },
				} );
				fillRow( row, item );
				say( __( 'Passkey renamed.', 'two-factor-passkey' ) );
			} catch ( error ) {
				say( errorMessage( error, __( 'The passkey could not be renamed.', 'two-factor-passkey' ) ) );
			}
		}

		async function remove( row ) {
			const name = row.querySelector( '.two-factor-passkey-name' ).textContent;
			let message = sprintf(
				/* translators: %s: passkey name */
				__( 'Remove the passkey “%s”? You will no longer be able to use it to sign in.', 'two-factor-passkey' ),
				name
			);
			if ( rowCount() === 1 ) {
				message += ' ' + __( 'If it is your only two-factor method, you will not be asked for a second step when you sign in.', 'two-factor-passkey' );
			}
			if ( ! window.confirm( message ) ) {
				return;
			}

			try {
				await wp.apiFetch( { path: base + '/' + encodeURIComponent( row.dataset.id ), method: 'DELETE' } );
				row.remove();
				toggleEmpty();
				say( __( 'Passkey removed.', 'two-factor-passkey' ) );
			} catch ( error ) {
				say( errorMessage( error, __( 'The passkey could not be removed.', 'two-factor-passkey' ) ) );
			}
		}

		el.addEventListener( 'click', function ( event ) {
			const target = event.target.closest( 'button' );
			if ( ! target || ! el.contains( target ) ) {
				return;
			}

			const row = target.closest( 'tr[data-id]' );
			if ( target.classList.contains( 'two-factor-passkey-add' ) ) {
				add();
			} else if ( row && target.classList.contains( 'two-factor-passkey-rename' ) ) {
				rename( row );
			} else if ( row && target.classList.contains( 'two-factor-passkey-remove' ) ) {
				remove( row );
			}
		} );

		el.addEventListener( 'keydown', function ( event ) {
			if ( event.key === 'Enter' && event.target.classList.contains( 'two-factor-passkey-new-name' ) ) {
				event.preventDefault();
				if ( ! addButton.disabled ) {
					add();
				}
			}
		} );
	}

	Array.prototype.forEach.call( document.querySelectorAll( '.two-factor-passkey-settings' ), init );
}() );
