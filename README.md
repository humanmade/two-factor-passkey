# Two Factor Passkey

Two Factor Passkey adds passkeys (WebAuthn) as a second-factor provider for the Human Made fork of the Two Factor plugin.

It is a second factor only. A passkey is a second step after the password, like an authenticator app code. There is no passwordless sign-in.

The plugin targets the `master` branch of [humanmade/two-factor](https://github.com/humanmade/two-factor). It is not tested against upstream [WordPress/two-factor](https://github.com/WordPress/two-factor) or the fork's 0.3.x tags.

The design notes are in [docs/PLAN.md](docs/PLAN.md).

## Requirements

- PHP 8.2 or later, with `ext-openssl` and `ext-mbstring`.
- WordPress 6.6 or later.
- The Human Made fork of Two Factor, active as a plugin or an mu-plugin.
- HTTPS. Plain HTTP works only on `localhost`.

## Installation

Clone or download this repository into `wp-content/plugins/two-factor-passkey/`, then activate it.

The WebAuthn library is bundled and prefixed in `vendor-prefixed/`, so there is no build step.

With Composer, add the repository as a VCS repository:

```json
{
	"repositories": [
		{ "type": "vcs", "url": "https://github.com/humanmade/two-factor-passkey" }
	],
	"require": {
		"humanmade/two-factor-passkey": "dev-main"
	}
}
```

The package type is `wordpress-plugin`, so the project needs `composer/installers` (or a similar installer) to put it in `wp-content/plugins/`. Without one, Composer puts it in `vendor/` and WordPress never loads it.

If Two Factor is not active, the plugin shows an admin notice and does nothing else.

## Using it

Users add passkeys under Profile, then Two-Factor Options. Adding the first passkey turns the provider on.

Administrators can rename and remove other users' passkeys. They cannot add them, because a passkey made by someone else would live on the wrong device.

At login, the passkey step comes after the password. The backup methods the user has set up stay available. The passkey step also works on the force-2FA takeover screen and in the session-expired login modal.

## How it works

- Challenges are single use and expire after 5 minutes. Each one is tied to the user, the ceremony (register or sign in) and the login nonce.
- Responses are accepted only from an exact list of origins. The list is built from the site, admin and login URLs.
- Attestation is `none`, so no trust decision rests on attestation.
- User verification is preferred, not required.
- Discoverable credentials are discouraged.
- If a passkey's sign counter goes backwards, the passkey is disabled and the login is rejected.
- Passkeys are stored in one user meta value per user, keyed by credential ID. A second user meta value holds an opaque user handle.

## Multisite and domains

The RP ID is the host of the site's own URL. A passkey works only on sites that share the RP ID it was created under.

On any other site, the login step still asks for a passkey but says that none can be used there. The user needs a backup method, or an administrator must remove the passkey.

On a subdomain network, you can share passkeys by using the network's main domain as the RP ID:

```php
add_filter( 'two_factor_passkey_rp_id', function () {
	return get_network()->domain;
} );
```

Every site must be a subdomain of that domain. Domain-mapped sites cannot share passkeys, because a browser only accepts an RP ID that is the page's host or a parent of it.

Changing the RP ID later makes existing passkeys stop working.

## Behind a proxy

WordPress must know that the request is HTTPS. The usual fix goes in `wp-config.php`:

```php
if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {
	$_SERVER['HTTPS'] = 'on';
}
```

Origins come from the configured URLs, never from request headers.

## Known limitations

These come from the fork's `master` branch, not from this plugin.

- XML-RPC and application-password logins skip every second factor, because there is no `authenticate` filter.
- There is no rate limiting on the second-factor step.
- There is no re-authentication before adding a passkey.

## Hooks

All hooks are filters unless noted.

| Hook | Arguments | Default |
| --- | --- | --- |
| `two_factor_passkey_rp_id` | `string $rp_id` | Host of `site_url()`. The result is lowercased. |
| `two_factor_passkey_rp_name` | `string $name` | The site title, or the RP ID if the title is empty. |
| `two_factor_passkey_allowed_origins` | `string[] $origins` | Origins of `site_url()`, `admin_url()` and `wp_login_url()`. |
| `two_factor_passkey_require_user_verification` | `bool $required` | `false` (preferred, not required). |
| `two_factor_passkey_challenge_ttl` | `int $ttl` | `300` seconds. The minimum is 30. Also used as the browser timeout. |
| `two_factor_passkey_credential_limit` | `int $limit, int $user_id` | `20` passkeys per user. The minimum is 1. |
| `two_factor_passkey_counter_regression` (action) | `WP_User $user, array $credential` | No callbacks. Fires after the passkey is flagged and before the login is rejected. |

Each origin is `scheme://host`, with `:port` only for a non-default port.

## Uninstall

Deleting the plugin removes every user's passkeys, user handles and pending challenges. On multisite, this covers the whole network, because user meta is shared.

Deactivating the plugin keeps the data. While it is inactive, Two Factor ignores the passkey provider, so a user whose only second factor is a passkey signs in with just a password. Make sure users have another method, such as backup codes, before you deactivate it.

## Development

Install dependencies. `composer install` also runs Strauss, which prefixes the bundled library:

```sh
composer install
npm install
```

Run the PHPUnit tests in wp-env:

```sh
npx wp-env start
npm run test:php
npm run test:php:multisite
npx wp-env stop
```

Run the end-to-end tests. They use Playwright on WordPress Playground at `http://localhost:9400`, with a Chromium virtual authenticator:

```sh
npm run test:e2e
```

Run the coding standard checks:

```sh
vendor/bin/phpcs
```

CI runs PHPCS, a PHP syntax check on 8.2 to 8.5, PHPUnit (PHP 8.2 with WordPress 6.6, PHP 8.5 with the latest WordPress, and multisite), the Playwright tests, and a check that `vendor-prefixed/` is up to date.

To update the bundled library, change the `lbuchs/webauthn` version in `composer.json`, run `composer update lbuchs/webauthn`, and commit `vendor-prefixed/`.

## Credits and licence

Licensed under GPL-2.0-or-later. See [LICENSE](LICENSE).

The plugin bundles [lbuchs/webauthn](https://github.com/lbuchs/WebAuthn) by Lukas Buchs, under the MIT licence. Its CBOR and ByteBuffer parts are by Thomas Bleeker.

Built by [Human Made](https://humanmade.com/).
