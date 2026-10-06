<?php
/**
 * Site URL helper for tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

/**
 * Sets the site and home URLs.
 *
 * The wp-env test site defines WP_SITEURL and WP_HOME, which beat update_option(),
 * so the options are overridden with filters that run after core's constant filters.
 * WordPress also builds site_url() with the scheme of the current request, so
 * $_SERVER['HTTPS'] is set to match the URL.
 */
trait Site_Url {

	/**
	 * Make siteurl and home return a URL. The test suite removes the filters afterwards.
	 *
	 * @param string $url URL without a trailing slash.
	 */
	protected function set_site_url( string $url ): void {
		update_option( 'siteurl', $url );
		update_option( 'home', $url );

		if ( strpos( $url, 'https://' ) === 0 ) {
			$_SERVER['HTTPS'] = 'on';
		} else {
			unset( $_SERVER['HTTPS'] );
		}

		$filter = function () use ( $url ) {
			return $url;
		};
		add_filter( 'pre_option_siteurl', $filter, 11 );
		add_filter( 'pre_option_home', $filter, 11 );
	}
}
