import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { expect, test } from '@playwright/test';
import { addVirtualAuthenticator, login, logout } from './helpers';

const FIXTURE = join( __dirname, '..', 'php', 'fixtures', 'chromium-virtual-authenticator.json' );

const isPasskeyRoute = ( method: string, url: string, suffix: string ): boolean =>
	method === 'POST' &&
	new RegExp( `/two-factor-passkey/v1/users/\\d+/passkeys${ suffix }$` ).test( decodeURIComponent( url ).replace( /[?&]_locale=.*$/, '' ) );

test.skip( process.env.CAPTURE_FIXTURE !== '1', 'Set CAPTURE_FIXTURE=1 to record the Chromium fixture.' );

test( 'records a Chromium virtual authenticator ceremony for PHPUnit', async ( { browser } ) => {
	const context = await browser.newContext();
	const page = await context.newPage();

	await login( page, 'admin', 'password' );
	await expect( page ).toHaveURL( /\/wp-admin\/(index\.php)?$/ );
	await addVirtualAuthenticator( page );
	await page.goto( '/wp-admin/profile.php' );

	const optionsResponse = page.waitForResponse( ( response ) =>
		isPasskeyRoute( response.request().method(), response.url(), '/options' )
	);
	const registerRequest = page.waitForRequest( ( request ) =>
		isPasskeyRoute( request.method(), request.url(), '' )
	);
	await page.locator( '.two-factor-passkey-add' ).click();
	const creationOptions = await ( await optionsResponse ).json();
	const registrationBody = ( await registerRequest ).postDataJSON();
	await expect( page.locator( '.two-factor-passkey-settings .two-factor-passkey-status' ) ).toHaveText( 'Passkey added.' );

	await logout( page );
	const assertionRequest = page.waitForRequest(
		( request ) => request.method() === 'POST' && request.url().includes( 'action=validate_2fa' )
	);

	let releaseScript: () => void = () => {};
	const scriptGate = new Promise< void >( ( resolve ) => {
		releaseScript = resolve;
	} );
	await page.route( '**/assets/js/login.js*', async ( route ) => {
		await scriptGate;
		await route.continue();
	} );

	await login( page, 'admin', 'password' );
	const loginRoot = page.locator( '.two-factor-passkey-login' );
	await expect( loginRoot ).toBeVisible();
	const requestOptions = JSON.parse( ( await loginRoot.getAttribute( 'data-options' ) ) as string );
	releaseScript();
	const assertionForm = new URLSearchParams( ( await assertionRequest ).postData() as string );
	const assertionResponse = JSON.parse( assertionForm.get( 'two_factor_passkey_response' ) as string );
	await expect( page ).toHaveURL( /\/wp-admin\/(index\.php)?$/ );

	const fixture = {
		rp_id: 'localhost',
		origin: 'http://localhost:9400',
		user_handle: creationOptions.user.id,
		creation_options: creationOptions,
		registration_response: registrationBody.credential,
		request_options: requestOptions,
		assertion_response: assertionResponse,
	};
	mkdirSync( dirname( FIXTURE ), { recursive: true } );
	writeFileSync( FIXTURE, JSON.stringify( fixture, null, '\t' ) + '\n' );

	await context.close();
} );
