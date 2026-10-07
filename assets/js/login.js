( function () {
	'use strict';

	const __ = wp.i18n.__;
	const passkeys = window.twoFactorPasskey;
	const root = document.querySelector( '.two-factor-passkey-login' );

	if ( ! root ) {
		return;
	}

	const button = root.querySelector( '.two-factor-passkey-start' );
	const status = root.querySelector( '.two-factor-passkey-status' );
	const unsupported = root.querySelector( '.two-factor-passkey-unsupported' );
	const field = root.querySelector( '[name="two_factor_passkey_response"]' );
	const form = root.closest( 'form' );

	if ( ! passkeys.isSupported() ) {
		if ( unsupported ) {
			unsupported.hidden = false;
		}
		button.hidden = true;
		return;
	}

	let options;
	try {
		options = JSON.parse( root.dataset.options );
	} catch ( e ) {
		return;
	}

	let submitted = false;

	function setStatus( message ) {
		status.textContent = message;
	}

	async function start() {
		if ( submitted || button.disabled ) {
			return;
		}

		button.disabled = true;
		setStatus( __( 'Waiting for your passkey…', 'two-factor-passkey' ) );

		try {
			const credential = await navigator.credentials.get( { publicKey: passkeys.toRequestOptions( options ) } );
			field.value = JSON.stringify( passkeys.credentialToJSON( credential ) );
			setStatus( __( 'Signing in…', 'two-factor-passkey' ) );
			submitted = true;
			HTMLFormElement.prototype.submit.call( form );
		} catch ( error ) {
			if ( error && error.name === 'NotAllowedError' ) {
				setStatus( __( 'The passkey request was cancelled or timed out. Select Use passkey to try again, or use another method below.', 'two-factor-passkey' ) );
			} else {
				setStatus( __( 'Your passkey could not be used. Select Use passkey to try again, or use another method below.', 'two-factor-passkey' ) );
			}
			button.disabled = false;
		}
	}

	button.addEventListener( 'click', start );
	start();
}() );
