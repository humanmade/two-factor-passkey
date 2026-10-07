import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from '@playwright/test';
import type { CDPSession, FrameLocator, Locator, Page } from '@playwright/test';

export const BACKUP_CODE = '12345678';

const SCREENSHOT_DIR = join( __dirname, '..', '..', 'artifacts', 'screenshots' );

export interface VirtualAuthenticator {
	client: CDPSession;
	authenticatorId: string;
}

/** Wait until the blueprint has created the last user it adds; Playground can report ready before that. */
export async function login( page: Page, user: string, pass: string ): Promise< void > {
	await page.goto( '/wp-login.php' );
	// wp-login.php focuses #user_login on a timer; fill after that so typing is not redirected.
	await expect( page.locator( '#user_login' ) ).toBeFocused();
	await page.locator( '#user_login' ).fill( user );
	await page.locator( '#user_pass' ).fill( pass );
	await expect( page.locator( '#user_login' ) ).toHaveValue( user );
	await expect( page.locator( '#user_pass' ) ).toHaveValue( pass );
	await page.locator( '#wp-submit' ).click();
}

export async function loginInFrame( frame: FrameLocator, user: string, pass: string ): Promise< void > {
	await expect( frame.locator( '#user_login' ) ).toBeFocused();
	await frame.locator( '#user_login' ).fill( user );
	await frame.locator( '#user_pass' ).fill( pass );
	await expect( frame.locator( '#user_login' ) ).toHaveValue( user );
	await expect( frame.locator( '#user_pass' ) ).toHaveValue( pass );
	await frame.locator( '#wp-submit' ).click();
}

export async function logout( page: Page ): Promise< void > {
	await page.goto( '/wp-login.php?action=logout' );
	await page.getByRole( 'link', { name: 'log out' } ).click();
	await page.locator( '#user_login' ).waitFor();
}

export async function addVirtualAuthenticator( page: Page ): Promise< VirtualAuthenticator > {
	const client = await page.context().newCDPSession( page );
	await client.send( 'WebAuthn.enable', { enableUI: false } );
	const { authenticatorId } = await client.send( 'WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'internal',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true,
		},
	} );
	return { client, authenticatorId };
}

export async function removeVirtualAuthenticator( { client, authenticatorId }: VirtualAuthenticator ): Promise< void > {
	await client.send( 'WebAuthn.removeVirtualAuthenticator', { authenticatorId } );
}

export async function saveScreenshot( target: Page | Locator, name: string ): Promise< string > {
	mkdirSync( SCREENSHOT_DIR, { recursive: true } );
	const path = join( SCREENSHOT_DIR, `${ name }.png` );
	await target.screenshot( { path } );
	return path;
}

/** Swap a virtual authenticator credential for a copy of itself with a different sign counter. */
export async function setCredentialSignCount( { client, authenticatorId }: VirtualAuthenticator, signCount: number ): Promise< void > {
	const { credentials } = await client.send( 'WebAuthn.getCredentials', { authenticatorId } );
	expect( credentials ).toHaveLength( 1 );
	const { credentialId, isResidentCredential, rpId, privateKey, userHandle } = credentials[ 0 ];
	await client.send( 'WebAuthn.removeCredential', { authenticatorId, credentialId } );
	await client.send( 'WebAuthn.addCredential', {
		authenticatorId,
		credential: { credentialId, isResidentCredential, rpId, privateKey, userHandle, signCount },
	} );
}

export async function getSignCount( { client, authenticatorId }: VirtualAuthenticator ): Promise< number > {
	const { credentials } = await client.send( 'WebAuthn.getCredentials', { authenticatorId } );
	return credentials[ 0 ].signCount;
}
