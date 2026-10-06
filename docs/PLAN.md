# Two Factor Passkey: implementation plan

This plugin adds passkeys (WebAuthn) as a second-factor provider for the Human Made fork of Two Factor. A passkey works like TOTP: it is a second step after the password. There is no passwordless sign-in.

Status: draft for Rob's approval. No plugin code has been written yet.

## Context and fixed decisions

- Target: `humanmade/two-factor` at `master` (last change January 2023), as Rob decided. The fork's 0.3.x tags come from the `force-2fa` branch (upstream 0.8.1 plus force-2FA), and `altis-security` requires `^0.3.4`. `master` is a different and older codebase. This plan uses only the `master` API. Supporting 0.3.x later would mean an adapter for different hook names, file names and core helpers (see open decision 12).
- Library: `lbuchs/webauthn` v2.2.0 (MIT, released July 2024). Its `master` branch has no functional changes since that tag. It needs PHP 8.0 or later, `ext-openssl` and `ext-mbstring`.
- Second factor only.

## What the fork's `master` gives us

- Providers are registered through the `two_factor_providers` filter as `class name => file path`. Core runs `include_once` on the path and calls `Class::get_instance()`. It does this on every `get_providers()` call, so the provider must be a singleton with no side effects outside its constructor.
- The class name is the provider key. It is stored in `_two_factor_enabled_providers` and `_two_factor_provider` user meta and used in form values and the `two-factor-user-options-{Class}` action. It must never change after release.
- The base class is `Two_Factor_Provider`, with `get_label()`, `authentication_page( $user )`, `pre_process_authentication( $user )`, `validate_authentication( $user )` and `is_available_for_user( $user )`.
- Login flow: `wp_login` clears the auth cookie and renders `login_html()`. That function creates a per-user login nonce (plain text in `_two_factor_nonce` user meta, valid for 1 hour) and prints a form that posts to `wp-login.php?action=validate_2fa`. Inside that form it calls the provider's `authentication_page()`. On POST, core checks the login nonce, then the provider: `pre_process_authentication()` first, then `validate_authentication()`. On failure it re-renders the page with a new nonce and a generic "Invalid verification code" error. Backup providers are linked under the form through `action=backup_2fa`.
- A provider is used only if it is both ticked in the profile ("enabled") and returns true from `is_available_for_user()`. If only one is available, it becomes primary. Otherwise the user's radio choice wins, falling back to the first available one.
- Profile screen: `user_two_factor_options()` prints a table with one row per provider (enabled checkbox, primary radio, label, then the `two-factor-user-options-{Class}` action). It then fires `show_user_security_settings`. Saving the profile overwrites the enabled list from the submitted checkboxes.
- Force-2FA takeover screen (`Two_Factor_Force`): a login-style page at `admin_url()?force_2fa_screen=1`. It reuses `user_two_factor_options()` and saves over admin-ajax (`two_factor_force_form_submit`, which fires `two_factor_ajax_options_update`). It skips its redirect for AJAX and REST requests. It enqueues U2F assets by hard-coded class name, so other providers have to enqueue their own. Scripts enqueued while the row renders still print, because `login_footer` runs `wp_print_footer_scripts`.
- `master` has no re-validation before settings changes, no rate limiting and no REST helpers. TOTP on `master` saves through the profile form.

### What we take from the U2F provider, and what we don't

We take: a singleton provider with its own admin hooks, scripts enqueued from `authentication_page()`, a hidden field with the browser's JSON response posted back to `validate_2fa`, and one stored record per key with name, added date and last-used date.

We don't copy:
- Challenges kept in user meta with no expiry and never consumed.
- Key deletion that acts on `get_current_user_id()` even on `user-edit.php`, so an admin deleting a user's key deletes their own instead.
- No capability checks beyond nonces.
- A full-page profile POST for registration, which does not work on the AJAX force screen.

## Provider registration and how it sits next to other providers

- Global adapter class `Two_Factor_Passkey extends Two_Factor_Provider`. The global name matches the fork's other providers and gives a readable meta value. Everything else lives under the `HM\Two_Factor_Passkey` namespace.
- Bootstrap on `plugins_loaded`. If `Two_Factor_Provider` does not exist, add an admin notice and stop. Otherwise add the provider through `two_factor_providers`.
- Label: "Passkey or security key".
- `is_available_for_user( $user )` returns true if the user has at least one stored credential, and nothing more. On `master` this one check does two jobs, so it must not depend on the request:
  - Login routing: if no provider is available, `get_primary_provider_for_user()` returns null, and `wp_login` lets the password through alone. If the check returned false on a domain-mapped site, over HTTP, or when every key is flagged, a user with only passkeys would skip the second factor. An attacker could trigger that by cloning a key.
  - Profile checkboxes: `user_two_factor_options()` ticks the boxes from the *available* providers, not the enabled list. If the check returned false on one site, the box would render unticked there, and saving the profile would remove the provider from the network-wide enabled list.
- So the context checks go into the login step instead:
  - the key's RP ID must match this site;
  - the key must not be flagged;
  - the page must be a secure context (HTTPS, or the host is `localhost`).

  `authentication_page()` explains why no key can be used here and points to the backup links that core prints. `validate_authentication()` rejects. If passkey is the user's only provider, they are locked out until an admin removes their keys or they use backup codes (open decision 13).
- No change to how the primary provider is chosen. The user picks it with the existing radio button. Backup codes, TOTP and email stay available as backup links under the passkey step.
- Adding the first passkey turns the provider on server side (it adds the class to `_two_factor_enabled_providers`). The JS also ticks the checkbox on the page, so a later profile save does not switch it off again (open decision 9).
- Removing the last passkey makes the provider unavailable, and core falls back to the next provider. If no other provider remains, the user no longer has 2FA. The remove dialog warns about this.

## Ceremonies

### Relying party ID and origins

- RP ID: by default, the host of `site_url()` (the host that serves `wp-login.php` and `wp-admin`). It can be changed with the `two_factor_passkey_rp_id` filter. Each credential stores the RP ID it was created under, and only matching credentials are offered or accepted.
- Multisite: by default each site uses its own host. A subdomain network may want the network domain, so one passkey works on every subdomain. That is valid WebAuthn because the network domain is a registrable suffix. A domain-mapped site can never share. Open decision 7.
- Allowed origins: an exact list of `scheme://host[:port]` values built from `site_url()`, `admin_url()` and `wp_login_url()`. The list covers `FORCE_SSL_ADMIN` setups where the schemes differ, and can be changed with the `two_factor_passkey_allowed_origins` filter. We check `clientDataJSON.origin` against this list before the library runs. The library's own check is a regex `rpId$` against the origin's host with no dot boundary, so `https://evilexample.com` passes for `example.com`. The browser would block that case anyway, but we want an exact match.
- Proxies: origins are built from the configured site URLs, never from request headers, so `X-Forwarded-Host` cannot change them. A TLS-terminating proxy still needs WordPress to know the request is HTTPS (the usual `X-Forwarded-Proto` handling in `wp-config.php`). Otherwise the generated URLs are `http://` and the origin check fails. The README will say this.
- The library accepts plain HTTP only when the RP ID is exactly `localhost`, and IP addresses are never valid RP IDs. Local and test sites must use `localhost`, not `127.0.0.1`.

### Challenges

- Stored in user meta, one key per ceremony: `_two_factor_passkey_challenge_create` and `_two_factor_passkey_challenge_get`. Each value is `{ challenge (base64url), expires, rp_id, login_nonce_hash (get only) }`.
- Why user meta and not transients: users are network-wide on multisite but transients are per site. A persistent object cache can also evict transients early. Core's login nonce already lives in user meta.
- Each challenge is 32 random bytes from the library (`random_bytes`) and lasts 5 minutes. The same 5 minutes is sent to the browser as `timeout`.
- Single use: the stored challenge is read and deleted before verification starts, whatever the result.
- Bound to the user (it lives in their meta) and to the ceremony (separate keys, and the library checks `clientDataJSON.type`). The login challenge is also bound to the login nonce. When `authentication_page()` runs, we store a hash of the nonce core has just written. `validate_authentication()` compares it with the posted `wp-auth-nonce`.
- If two tabs are open, the newest challenge wins and the older tab fails with a clear error. That is acceptable.

### Registration (profile screen and force-2FA screen)

REST routes under `two-factor-passkey/v1`, called with `wp.apiFetch`. We use REST because the force screen has no full-page submit, and because REST requests skip the force-2FA redirect.

- `POST /users/{id}/passkeys/options`: returns `PublicKeyCredentialCreationOptions` and stores the create challenge.
- `POST /users/{id}/passkeys`: body is `{ name, credential }`. Verifies the credential, stores it, turns on the provider and returns the new row.
- `PATCH /users/{id}/passkeys/{credential_id}`: renames a passkey.
- `DELETE /users/{id}/passkeys/{credential_id}`: removes a passkey.

Permissions:
- All routes need cookie authentication with a valid `wp_rest` nonce (the `X-WP-Nonce` header, which `wp-api-fetch` adds). Requests authenticated by an application password are refused. An application password should not be able to add or remove a second factor.
- Options and create: only for your own account (`{id} === get_current_user_id()`). A passkey created by an admin would live on the admin's device and be useless to the user.
- Rename and delete: `current_user_can( 'edit_user', $id )`. This covers admins and network super admins handling other users. The route acts on `{id}`, never on the current user.

Creation options:
- `user.id` is an opaque random 32-byte handle per user (`_two_factor_passkey_user_handle`), never the WordPress user ID or login.
- `user.name` is the login and `user.displayName` is the display name.
- `excludeCredentials` lists the user's existing credentials, so the same authenticator cannot be added twice.
- `attestation: "none"` (open decision 3), `userVerification: "preferred"` (open decision 4), `residentKey: "discouraged"` (open decision 5).
- Algorithms come from the library: EdDSA, ES256 and RS256.

Verification: we run `processCreate()` after our origin check. We require user presence. We require user verification only if the `two_factor_passkey_require_user_verification` filter says so. We reject a credential ID the user already has, and enforce a per-user limit of 20 (filterable).

### Authentication (login step)

There is no extra endpoint here. It uses core's existing form and login nonce.

1. `authentication_page( $user )` calls `getGetArgs()` with `allowCredentials` set to the user's credentials for this RP ID. It stores the get challenge and passes the options to the script. It renders a short message, a "Use passkey" button, a hidden `two_factor_passkey_response` field, and a `<noscript>` note.
2. The script calls `navigator.credentials.get()` straight away. Some browsers require a user gesture, so if the call is refused it waits for the button. On success it fills the hidden field and submits the form. If the browser has no WebAuthn support, the page says so and points to the backup methods that core lists under the form.
3. `validate_authentication( $user )` runs these checks:
   - read and delete the challenge, then check that it has not expired, that its RP ID matches, and that its nonce hash matches;
   - decode the response and look up `credential.id` among the user's own credentials for this RP ID. This is the `allowCredentials` check, which the library leaves to us;
   - reject flagged credentials;
   - if `userHandle` is present, check that it equals the user's handle (the library leaves this to us too);
   - run our origin check;
   - call `processGet()` with the stored public key and the previous sign counter;
   - on success, update `sign_count` and `last_used`.

### Sign counter and cloned authenticators

- Each credential stores the latest `sign_count`. Synced passkeys always report 0. The library only complains when either value is non-zero and the new value is not higher than the stored one.
- When that happens, the signature has already been checked. The library throws `SIGNATURE_COUNTER`. Our recommendation (open decision 6):
  - reject the login and mark the credential `flagged_at`;
  - flagged credentials cannot be used for login and appear as "possibly cloned" on the profile screen;
  - fire the `two_factor_passkey_counter_regression` action with the user and credential, so sites can alert or log it;
  - the user removes the key and adds it again. Backup codes cover the gap.

## Credential storage

One user meta row per user, `_two_factor_passkey_credentials`. It holds an array keyed by the base64url credential ID:

```php
[
	'Q2hyb21lVmlydHVhbA' => [
		'id'              => 'Q2hyb21lVmlydHVhbA', // base64url credential ID.
		'public_key'      => "-----BEGIN PUBLIC KEY-----\n...",
		'sign_count'      => 0,
		'rp_id'           => 'example.com',
		'name'            => 'Work laptop',
		'aaguid'          => '00000000-0000-0000-0000-000000000000',
		'transports'      => [ 'internal', 'hybrid' ],
		'backup_eligible' => true,
		'backed_up'       => true,
		'user_verified'   => true,  // UV flag at registration.
		'created_at'      => 1759750000,
		'last_used_at'    => null,
		'flagged_at'      => null,
	],
]
```

- One array, not one meta row per key. During login the user is already known, so we never search across users, and the list is small. Rename and delete become a simple read, change, write.
- No global uniqueness check across users. The WebAuthn spec asks for one so that a discoverable login cannot be mapped to the wrong account. In a second-factor flow we only look at the signed-in user's own keys, so a duplicate on another account cannot be used. The PR will say this.
- We don't store attestation certificates. We make no trust decision from them (see attestation).
- Names: plain text, at most 100 characters, filtered with `sanitize_text_field`. The default is "Passkey N". We don't map AAGUIDs to authenticator names in v1.
- Uninstall (`uninstall.php`) removes every `_two_factor_passkey_*` meta key. On multisite it does the same, because user meta is network-wide.

## Profile UI

- Shown inside the provider's row through `two-factor-user-options-Two_Factor_Passkey`, so it appears on both `profile.php` and `user-edit.php`, and on the force-2FA screen.
- Content:
  - a list of keys: name, added date, last-used date, a "synced" badge when `backed_up` is set, and a "possibly cloned" badge when flagged;
  - Rename and Remove buttons on each row;
  - on your own profile, an "Add a passkey" button with an optional name field. On someone else's profile, the text "Only the user can add passkeys."
- Plain markup and vanilla JS. Dependencies: `wp-api-fetch`, `wp-i18n` and `wp-a11y` (to announce results). There is no build step and no `WP_List_Table`, because the force screen is a login-style page without admin includes.
- Every button is `type="button"`, so pressing Enter in the name field never submits the surrounding profile or force form.
- Shows a note instead of the add button when the page is not in a secure context.
- Base64url conversion: use `PublicKeyCredential.parseCreationOptionsFromJSON()`, `parseRequestOptionsFromJSON()` and `credential.toJSON()` where the browser has them. Otherwise use a small helper (about 20 lines). The library is set to `ByteBuffer::$useBase64UrlEncoding = true`, so its JSON already matches the WebAuthn JSON format.

## Shipping the library

- Prefix with Strauss (`brianhenryie/strauss`, currently 0.30.x). Namespace: `HM\Two_Factor_Passkey\Vendor\lbuchs\WebAuthn`. Target directory: `vendor-prefixed/`. Strauss also prefixes the static `ByteBuffer::$useBase64UrlEncoding`, so our setting cannot affect, or be affected by, another plugin's copy.
- `lbuchs/webauthn` goes in `require-dev`, with Strauss's `packages` and `delete_vendor_packages` set. If a site installs our plugin with Composer, it then gets no second, unprefixed copy in its root `vendor/`.
- Commit `vendor-prefixed/` (open decision 10). The plugin then works from a git checkout or a zip with no build step. A CI job runs Strauss again and fails if `git diff` is not empty.
- Runtime loading: `vendor-prefixed/autoload.php` plus `require_once` for our own files. There is no Composer autoloader at runtime.
- Licence: the library is MIT (Lukas Buchs; the CBOR and ByteBuffer parts are by Thomas Bleeker), which is compatible with GPL-2.0. We keep its `LICENSE` file inside `vendor-prefixed/` and credit it in the README. Strauss adds a "modified by" note to the file headers, which MIT allows.
- Composer metadata: `"type": "wordpress-plugin"`, `"require": { "php": ">=8.2", "ext-openssl": "*", "ext-mbstring": "*" }`. We don't put `humanmade/two-factor` in `require` (open decision 2).

## Testing

### PHPUnit (server side)

- Uses the WordPress test suite with `humanmade/two-factor:dev-master` installed as a dev dependency and loaded in the bootstrap.
- A test helper `Soft_Authenticator` creates an ES256 key with OpenSSL, builds `authData` (RP ID hash, flags, counter, attested credential data), and encodes a `none` attestation with a tiny CBOR encoder (maps, byte and text strings, integers only). It signs assertions. With this we can build any valid or broken response.
- One registration and one login captured from the Chromium virtual authenticator are committed as fixtures. They prove the helper matches what a real browser sends.
- Cases:
  - registration succeeds and stores the expected shape;
  - wrong origin, including the `evilexample.com` suffix case;
  - wrong RP ID hash;
  - wrong `type`;
  - wrong, expired, replayed (second use) and other-user challenge;
  - create challenge used for get, and the reverse;
  - login nonce mismatch;
  - credential that belongs to another user;
  - unknown credential;
  - `userHandle` mismatch;
  - counter regression flags the credential and later logins fail;
  - counter 0/0 passes;
  - UV required but not set;
  - user presence missing;
  - duplicate registration;
  - credential limit;
  - `is_available_for_user` stays true whenever keys exist, while the login step rejects an RP ID mismatch, flagged keys and a non-secure context;
  - REST permissions: own account only for create; `edit_user` for rename and delete; application password refused; missing nonce refused; an admin deleting another user's key acts on that user.

### Playwright end to end

- WordPress Playground CLI (`@wp-playground/cli`) started by Playwright's `webServer` on `http://localhost:9400`. The site URL must be `localhost`, not `127.0.0.1`, because IP addresses are not valid RP IDs. I haven't yet checked the exact CLI flag for setting the site URL; checkpoint 1 confirms it. A blueprint installs the fork from `https://github.com/humanmade/two-factor/archive/refs/heads/master.zip` (it unpacks as `two-factor-master/`, which is fine because we check for the class, not the slug), mounts this plugin, and creates an admin and an editor.
- Chromium only, `workers: 1`. Each test opens a CDP session and calls `WebAuthn.enable`, then `WebAuthn.addVirtualAuthenticator` with `{ protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }`.
- Scenarios:
  - add a passkey on the profile screen;
  - log out, log in with the password, pass the passkey step, reach the dashboard;
  - swap in a new virtual authenticator, see the failure, recover with backup codes;
  - rename and remove a passkey;
  - an admin removes the editor's passkey;
  - add a passkey on the force-2FA screen and reach the dashboard;
  - the interim login (session-expired modal) with a passkey.
- Screenshots of the profile screen and the login step are saved and attached to each PR. Traces are kept when a test fails.
- Process hygiene: one browser at a time. Playwright starts and stops Playground. After each local run, `pgrep -f playground` and `pgrep -f chrom` must return nothing.
- First thing to check in checkpoint 1: that Playground's PHP build has working OpenSSL EC support (`openssl_get_curve_names()` includes `prime256v1`, and `openssl_verify` works with ES256). If not, E2E needs another environment.

### Local environment

Playground CLI for E2E (as briefed). For PHPUnit we recommend `@wordpress/env` (Docker, which is installed here), because it ships a PHPUnit-ready tests container with MySQL. Open decision 11.

## Human Made standards and CI

- PHPCS: `humanmade/coding-standards` v2.5 (`HM` ruleset). The global `Two_Factor_Passkey` adapter gets a targeted exclusion for the namespace and file-name sniffs. Files follow HM layout: `plugin.php`, `inc/namespace.php`, `inc/class-*.php`.
- GitHub Actions, triggered on pull requests and pushes to `main`:
  - `lint`: PHPCS, plus `php -l` on PHP 8.2 to 8.5.
  - `phpunit`: on PHP 8.2 and 8.5, against the minimum WordPress version and the latest.
  - `e2e`: Playground plus Playwright. Uploads screenshots, and traces on failure.
  - `vendor`: runs Strauss and checks there is no diff.
- README: what it does, requirements, installation, how ceremonies and storage work, proxy and multisite notes, filters and actions, development setup, and library credit.

## Known risks

- The fork's `master` uses the same U2F library code that needed a PHP 8.4 fix on `force-2fa`. Expect deprecation notices on PHP 8.4 and later from the fork, not from us. E2E will show whether anything is fatal.
- `master` has no re-validation. Anyone holding a logged-in session can add a passkey without re-entering the password or second factor (open decision 8).
- `master` has no rate limiting on the 2FA step. Passkeys cannot be brute-forced, but other providers on the same account can. That is out of scope here.
- `master` hooks only `wp_login` and has no `authenticate` filter, unlike 0.3.4 (the fork also has an unmerged `fix/xmlrpc-bypass` branch). XML-RPC and application-password logins never reach `wp_login`, so they skip every second factor, passkeys included. This plugin cannot fix that. It is a property of the chosen base.

## Delivery checkpoints

Each checkpoint is one branch and one PR against `main`.

1. **Foundation.** Plugin bootstrap and dependency check, the provider adapter, credential storage, challenge store, RP ID and origin handling, and server-side verification of both ceremonies through the prefixed library. Also Strauss, PHPCS, the PHPUnit suite with `Soft_Authenticator`, and the CI jobs `lint`, `phpunit` and `vendor`. No UI yet.
2. **Ceremonies in the browser.** REST routes, the profile UI, the login step script, and the Playwright suite in CI with screenshots of the profile and login step on the PR.
3. **Hardening and docs.** The force-2FA screen, multisite RP ID behaviour, counter-regression UI and action, interim login, uninstall, the README, and the remaining E2E scenarios.

## Open decisions for Rob

Each has a recommendation.

1. **Minimum versions.** Recommend PHP 8.2 (the library needs 8.0, 8.1 has been end-of-life since December 2025, and Altis requires 8.2) and WordPress 6.6. Nothing in the plugin needs a newer WordPress API. CI tests the minimum and the latest.
2. **Declaring the dependency on two-factor.** Recommend a runtime check (`class_exists( 'Two_Factor_Provider' )`) with an admin notice. No `Requires Plugins: two-factor` header: it only sees plugins in `wp-content/plugins` with that exact slug, so it blocks activation where two-factor is loaded as an mu-plugin or by Composer. Also, the fork's headers (`Version: 0.1-dev`) give us nothing to pin against. Composer lists `humanmade/two-factor` under `suggest` only.
3. **Attestation.** Recommend requesting `none`, accepting any format the library knows, and loading no root certificates, so we make no trust decision from attestation. Restricting to `['none']` only would make registration fail if a browser or authenticator still sends self-attestation. If a client later needs "only these authenticator models", that is a separate feature (AAGUID allow-list plus the FIDO Metadata Service).
4. **User verification.** Recommend `preferred` in requests, not required at verification. The password is already the first factor, and requiring UV would force a PIN on many security keys. A filter lets a site require it.
5. **Resident (discoverable) keys.** Recommend `discouraged`. Second-factor use does not need a discoverable credential, and this saves the limited slots on hardware keys. Phones and password managers still create synced passkeys. The trade-off: passwordless sign-in later would need users to add their keys again.
6. **Cloned-authenticator policy.** Recommend: reject the login, flag and disable the key, show it on the profile, and fire an action. Other options are to reject only that one attempt, or to log and allow.
7. **Multisite RP ID.** Recommend each site's own host by default, with a filter, plus documented code to use the network domain on subdomain networks. We don't recommend the network domain as default, because domain-mapped sites would silently lose their keys.
8. **Re-authentication before adding a passkey.** `master` has no re-validation. Recommend v1 matches TOTP on `master` (no extra step) and the README states the risk. The alternative is to ask for the password again before showing creation options. That adds a small step and some code.
9. **Turning the provider on automatically after the first passkey.** Recommend yes, server side plus the checkbox on the page. Otherwise a user can add a key, forget the checkbox, and think they are protected.
10. **Committing `vendor-prefixed/`.** Recommend committing it, with a CI drift check. The alternative is a release build that produces a zip. That needs release tooling and means a plain git checkout does not work.
11. **PHPUnit environment.** Recommend `@wordpress/env` for PHPUnit (Docker), next to Playground for E2E. Alternatives: Playground for both (the WP test suite on SQLite needs extra wiring), or ddev.
12. **Fork 0.3.x / Altis.** Out of scope for v1 by Rob's decision. Noted only so the provider class name and meta keys are chosen to stay the same if an adapter is added later.
13. **No usable passkey at the login step.** This covers a user whose only provider is passkey, when none of their keys can be used on this request (another RP ID, all flagged, or not HTTPS). Recommend blocking the login: the passkey step shows why and offers any backup methods, and an admin can remove the keys. That is the safe failure for a 2FA plugin. The alternative is to skip the second factor. `master` has no middle ground, because the same availability check drives both login routing and the profile checkboxes.
