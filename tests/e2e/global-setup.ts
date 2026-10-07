import { request } from '@playwright/test';
import type { FullConfig } from '@playwright/test';

/**
 * Wait for the blueprint to finish.
 *
 * Playground answers requests before its runPHP step has run, so this waits
 * until `contributor`, the last thing that step creates, exists.
 */
export default async function globalSetup( config: FullConfig ): Promise< void > {
	const context = await request.newContext( { baseURL: config.projects[ 0 ].use.baseURL } );
	const deadline = Date.now() + 60_000;

	try {
		while ( Date.now() < deadline ) {
			const response = await context.post( '/wp-login.php', { form: { log: 'contributor', pwd: 'wrong' } } );
			if ( ! ( await response.text() ).includes( 'is not registered' ) ) {
				return;
			}
			await new Promise( ( resolve ) => setTimeout( resolve, 500 ) );
		}
		throw new Error( 'The Playground blueprint did not finish within 60 seconds.' );
	} finally {
		await context.dispose();
	}
}
