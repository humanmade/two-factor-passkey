import { expect, test } from '@playwright/test';
import type { BrowserContext, Page } from '@playwright/test';
import {
	BACKUP_CODE,
	addVirtualAuthenticator,
	login,
	logout,
	removeVirtualAuthenticator,
	saveScreenshot,
} from './helpers';
import type { VirtualAuthenticator } from './helpers';

const PROVIDER = 'Two_Factor_Passkey';
const DASHBOARD = /\/wp-admin\/(index\.php)?$/;

const enabledCheckbox = ( page: Page, provider: string ) =>
	page.locator( `input[name="_two_factor_enabled_providers[]"][value="${ provider }"]` );
const primaryRadio = ( page: Page, provider: string ) =>
	page.locator( `input[name="_two_factor_provider"][value="${ provider }"]` );
const rows = ( page: Page ) => page.locator( '.two-factor-passkey-table tbody tr[data-id]' );
const status = ( page: Page ) => page.locator( '.two-factor-passkey-settings .two-factor-passkey-status' );

test.describe.configure( { mode: 'serial' } );

test.describe( 'passkey second factor', () => {
	let context: BrowserContext;
	let page: Page;
	let authenticator: VirtualAuthenticator;

	test.beforeAll( async ( { browser } ) => {
		context = await browser.newContext();
		page = await context.newPage();
	} );

	test.afterAll( async () => {
		await context.close();
	} );

	test( 'adds a passkey on the profile', async () => {
		await login( page, 'admin', 'password' );
		await expect( page ).toHaveURL( DASHBOARD );
		authenticator = await addVirtualAuthenticator( page );

		await page.goto( '/wp-admin/profile.php' );
		await page.locator( '#two-factor-passkey-new-name' ).fill( 'Test laptop' );
		await page.locator( '.two-factor-passkey-add' ).click();

		await expect( status( page ) ).toHaveText( 'Passkey added.' );
		await expect( rows( page ) ).toHaveCount( 1 );
		await expect( rows( page ).first() ).toContainText( 'Test laptop' );
		await expect( enabledCheckbox( page, PROVIDER ) ).toBeChecked();

		await primaryRadio( page, PROVIDER ).check();
		await page.locator( '#submit' ).click();
		await expect( page.locator( '#message' ) ).toContainText( 'Profile updated.' );

		await page.reload();
		await expect( rows( page ) ).toHaveCount( 1 );
		await expect( rows( page ).first() ).toContainText( 'Test laptop' );
		await expect( enabledCheckbox( page, PROVIDER ) ).toBeChecked();
		await expect( primaryRadio( page, PROVIDER ) ).toBeChecked();

		await saveScreenshot(
			page.locator( '.two-factor-methods-table tr', { has: page.locator( '.two-factor-passkey-settings' ) } ),
			'profile-passkeys'
		);
	} );

	test( 'logs in with a passkey', async () => {
		await logout( page );

		let releaseScript: () => void = () => {};
		const scriptGate = new Promise< void >( ( resolve ) => {
			releaseScript = resolve;
		} );
		await page.route( '**/assets/js/login.js*', async ( route ) => {
			await scriptGate;
			await route.continue();
		} );

		await login( page, 'admin', 'password' );
		await expect( page.locator( 'form#loginform .two-factor-passkey-login' ) ).toBeVisible();
		await saveScreenshot( page.locator( '#login' ), 'login-passkey-step' );

		releaseScript();
		await expect( page ).toHaveURL( DASHBOARD );
		await page.unroute( '**/assets/js/login.js*' );

		await page.goto( '/wp-admin/profile.php' );
		await expect( rows( page ).first().locator( '.column-last-used' ) ).not.toHaveText( 'Never' );
		await expect( rows( page ).first().locator( '.column-last-used' ) ).not.toBeEmpty();
	} );

	test( 'falls back to backup codes when the passkey is not available', async () => {
		await page.goto( '/wp-admin/profile.php' );
		await enabledCheckbox( page, 'Two_Factor_Backup_Codes' ).check();
		await expect( primaryRadio( page, PROVIDER ) ).toBeChecked();
		await page.locator( '#submit' ).click();
		await expect( page.locator( '#message' ) ).toContainText( 'Profile updated.' );
		await expect( enabledCheckbox( page, 'Two_Factor_Backup_Codes' ) ).toBeChecked();

		await removeVirtualAuthenticator( authenticator );
		authenticator = await addVirtualAuthenticator( page );

		await logout( page );
		await login( page, 'admin', 'password' );
		await expect( page.locator( 'form#loginform .two-factor-passkey-login' ) ).toBeVisible();

		const loginStatus = page.locator( '.two-factor-passkey-login .two-factor-passkey-status' );
		await expect( loginStatus ).toContainText( /passkey/i );
		await expect( loginStatus ).not.toContainText( /Waiting|Signing in/ );
		await expect( page.locator( '.two-factor-passkey-start' ) ).toBeEnabled();
		await saveScreenshot( page.locator( '#login' ), 'login-passkey-failed' );

		await page.locator( '.backup-methods a' ).click();
		await page.locator( '#authcode' ).fill( BACKUP_CODE );
		await page.getByRole( 'button', { name: 'Submit' } ).click();
		await expect( page ).toHaveURL( DASHBOARD );
	} );

	test( 'renames and removes a passkey', async () => {
		await page.goto( '/wp-admin/profile.php' );
		await expect( rows( page ) ).toHaveCount( 1 );

		page.once( 'dialog', ( dialog ) => dialog.accept( 'Work laptop' ) );
		await rows( page ).first().locator( '.two-factor-passkey-rename' ).click();
		await expect( rows( page ).first().locator( '.two-factor-passkey-name' ) ).toHaveText( 'Work laptop' );
		await expect( status( page ) ).toHaveText( 'Passkey renamed.' );

		page.once( 'dialog', ( dialog ) => dialog.accept() );
		await rows( page ).first().locator( '.two-factor-passkey-remove' ).click();
		await expect( rows( page ) ).toHaveCount( 0 );
		await expect( page.locator( '.two-factor-passkey-empty' ) ).toBeVisible();
		await expect( status( page ) ).toHaveText( 'Passkey removed.' );
	} );

	test( 'lets an admin remove another user\'s passkey', async ( { browser } ) => {
		const editorContext = await browser.newContext();
		const editorPage = await editorContext.newPage();

		try {
			await login( editorPage, 'editor', 'password' );
			await expect( editorPage ).toHaveURL( DASHBOARD );
			await addVirtualAuthenticator( editorPage );

			await editorPage.goto( '/wp-admin/profile.php' );
			await editorPage.locator( '#two-factor-passkey-new-name' ).fill( 'Editor key' );
			await editorPage.locator( '.two-factor-passkey-add' ).click();
			await expect( status( editorPage ) ).toHaveText( 'Passkey added.' );
			await expect( rows( editorPage ) ).toHaveCount( 1 );
			const editorId = await editorPage.locator( '.two-factor-passkey-settings' ).getAttribute( 'data-user-id' );

			await page.goto( `/wp-admin/user-edit.php?user_id=${ editorId }` );
			await expect( rows( page ) ).toHaveCount( 1 );
			await expect( rows( page ).first() ).toContainText( 'Editor key' );
			await expect( page.locator( '.two-factor-passkey-add' ) ).toHaveCount( 0 );
			await saveScreenshot(
				page.locator( '.two-factor-methods-table tr', { has: page.locator( '.two-factor-passkey-settings' ) } ),
				'user-edit-other-user'
			);

			page.once( 'dialog', ( dialog ) => dialog.accept() );
			await rows( page ).first().locator( '.two-factor-passkey-remove' ).click();
			await expect( rows( page ) ).toHaveCount( 0 );
			await expect( status( page ) ).toHaveText( 'Passkey removed.' );

			await logout( editorPage );
			await login( editorPage, 'editor', 'password' );
			await expect( editorPage ).toHaveURL( DASHBOARD );
			await expect( editorPage.locator( '.two-factor-passkey-login' ) ).toHaveCount( 0 );
		} finally {
			await editorContext.close();
		}
	} );
} );
