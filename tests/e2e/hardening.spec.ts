import { expect, test } from '@playwright/test';
import type { BrowserContext, Page } from '@playwright/test';
import {
	addVirtualAuthenticator,
	login,
	loginInFrame,
	logout,
	saveScreenshot,
	setCredentialSignCount,
} from './helpers';
import type { VirtualAuthenticator } from './helpers';

const PROVIDER = 'Two_Factor_Passkey';
const DASHBOARD = /\/wp-admin\/(index\.php)?$/;
const LOGIN_SCRIPT = '**/assets/js/login.js*';

const enabledCheckbox = ( page: Page ) =>
	page.locator( `input[name="_two_factor_enabled_providers[]"][value="${ PROVIDER }"]` );
const rows = ( page: Page ) => page.locator( '.two-factor-passkey-table tbody tr[data-id]' );
const status = ( page: Page ) => page.locator( '.two-factor-passkey-settings .two-factor-passkey-status' );

async function holdLoginScript( page: Page ): Promise< () => void > {
	let release: () => void = () => {};
	const gate = new Promise< void >( ( resolve ) => {
		release = resolve;
	} );
	await page.route( LOGIN_SCRIPT, async ( route ) => {
		await gate;
		await route.continue();
	} );
	return release;
}

test.describe.configure( { mode: 'serial' } );

test.describe( 'hardening', () => {
	let authorContext: BrowserContext;
	let author: Page;

	test.beforeAll( async ( { browser } ) => {
		authorContext = await browser.newContext();
		author = await authorContext.newPage();
	} );

	test.afterAll( async () => {
		await authorContext.close();
	} );

	test( 'forces a passkey to be added on the takeover screen', async () => {
		await login( author, 'author', 'password' );
		await expect( author ).toHaveURL( /force_2fa_screen=1/ );
		await expect( author.locator( '#force_2fa_form' ) ).toBeVisible();
		await addVirtualAuthenticator( author );

		await author.locator( '#two-factor-passkey-new-name' ).fill( 'Author key' );
		await author.locator( '.two-factor-passkey-add' ).click();
		await expect( status( author ) ).toHaveText( 'Passkey added.' );
		await expect( rows( author ) ).toHaveCount( 1 );
		await expect( rows( author ).first() ).toContainText( 'Author key' );
		await expect( enabledCheckbox( author ) ).toBeChecked();
		await saveScreenshot( author.locator( '#force_2fa_form' ), 'force-2fa-screen' );

		await author.locator( '#force_2fa_form' ).getByRole( 'button', { name: 'Submit' } ).click();
		await expect( author ).toHaveURL( DASHBOARD );
		await expect( author.locator( '#force_2fa_form' ) ).toHaveCount( 0 );

		await logout( author );
		await login( author, 'author', 'password' );
		await expect( author ).toHaveURL( DASHBOARD );
	} );

	test( 'disables a passkey whose sign counter goes backwards', async ( { browser } ) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		const adminContext = await browser.newContext();
		const adminPage = await adminContext.newPage();

		try {
			await login( page, 'contributor', 'password' );
			await expect( page ).toHaveURL( DASHBOARD );
			const authenticator: VirtualAuthenticator = await addVirtualAuthenticator( page );

			await page.goto( '/wp-admin/profile.php' );
			await page.locator( '#two-factor-passkey-new-name' ).fill( 'Contributor key' );
			await page.locator( '.two-factor-passkey-add' ).click();
			await expect( status( page ) ).toHaveText( 'Passkey added.' );
			await expect( rows( page ) ).toHaveCount( 1 );
			const userId = await page.locator( '.two-factor-passkey-settings' ).getAttribute( 'data-user-id' );

			await setCredentialSignCount( authenticator, 100 );
			await logout( page );
			await login( page, 'contributor', 'password' );
			await expect( page ).toHaveURL( DASHBOARD );

			await setCredentialSignCount( authenticator, 5 );
			await logout( page );
			await login( page, 'contributor', 'password' );
			await expect( page.locator( '.two-factor-passkey-error' ) ).toContainText( 'may have been copied' );
			await expect( page ).not.toHaveURL( DASHBOARD );

			await login( adminPage, 'admin', 'password' );
			await expect( adminPage ).toHaveURL( DASHBOARD );
			await adminPage.goto( `/wp-admin/user-edit.php?user_id=${ userId }` );
			await expect( rows( adminPage ) ).toHaveCount( 1 );
			await expect( rows( adminPage ).first().locator( '.two-factor-passkey-badge.is-flagged' ) ).toBeVisible();
			await saveScreenshot(
				adminPage.locator( '.two-factor-methods-table tr', { has: adminPage.locator( '.two-factor-passkey-settings' ) } ),
				'profile-flagged'
			);
		} finally {
			await context.close();
			await adminContext.close();
		}
	} );

	test( 'completes the passkey step inside the session-expired modal', async () => {
		await author.goto( '/wp-admin/' );
		await expect( author ).toHaveURL( DASHBOARD );

		await authorContext.clearCookies();
		await author.evaluate( () => {
			// Same event heartbeat fires when the session has expired.
			( window as any ).jQuery( document ).trigger( 'heartbeat-tick', [ { 'wp-auth-check': false } ] );
		} );

		const wrap = author.locator( '#wp-auth-check-wrap' );
		const modal = author.locator( '#wp-auth-check' );
		await expect( wrap ).not.toHaveClass( /hidden/ );
		await expect( modal ).toBeVisible();
		await expect( modal.locator( 'iframe' ) ).toHaveAttribute( 'src', /wp-login\.php\?.*interim-login=1/ );

		const frame = author.frameLocator( '#wp-auth-check-frame' );
		const releaseScript = await holdLoginScript( author );
		await loginInFrame( frame, 'author', 'password' );
		await expect( frame.locator( 'form#loginform .two-factor-passkey-login' ) ).toBeVisible();
		await saveScreenshot( modal, 'interim-login-passkey' );
		releaseScript();

		await expect( wrap ).toHaveClass( /hidden/ );
		await author.unroute( LOGIN_SCRIPT );
		await author.goto( '/wp-admin/' );
		await expect( author ).toHaveURL( DASHBOARD );
	} );
} );
