import { defineConfig, devices } from '@playwright/test';

const PORT = 9400;
const PLAYGROUND_VERSION = '3.1.57';
const PLUGIN_DIR = '/wordpress/wp-content/plugins/two-factor-passkey';

const mounts = [ 'plugin.php', 'inc', 'assets', 'vendor-prefixed' ]
	.map( ( path ) => `--mount=${ __dirname }/${ path }:${ PLUGIN_DIR }/${ path }` )
	.join( ' ' );

export default defineConfig( {
	testDir: 'tests/e2e',
	outputDir: 'test-results',
	fullyParallel: false,
	workers: 1,
	retries: process.env.CI ? 1 : 0,
	reporter: process.env.CI ? [ [ 'github' ], [ 'list' ] ] : 'list',
	globalSetup: './tests/e2e/global-setup.ts',
	use: {
		baseURL: `http://localhost:${ PORT }`,
		trace: 'retain-on-failure',
	},
	projects: [
		{
			name: 'chromium',
			use: { ...devices[ 'Desktop Chrome' ] },
		},
	],
	webServer: {
		command: `npx @wp-playground/cli@${ PLAYGROUND_VERSION } server --php=8.2 --port=${ PORT } --site-url=http://localhost:${ PORT } --blueprint=tests/e2e/blueprint.json ${ mounts }`,
		url: `http://localhost:${ PORT }/wp-login.php`,
		timeout: 240_000,
		reuseExistingServer: false,
		stdout: 'pipe',
		stderr: 'pipe',
	},
} );
