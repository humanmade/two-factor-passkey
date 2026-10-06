<?php
/**
 * Base64url tests.
 *
 * @package two-factor-passkey
 */

namespace HM\Two_Factor_Passkey\Tests;

use HM\Two_Factor_Passkey\Base64url;
use WP_UnitTestCase;

/**
 * Tests for Base64url.
 */
class Base64url_Test extends WP_UnitTestCase {

	public function test_round_trip() {
		for ( $length = 1; $length < 40; $length++ ) {
			$data = random_bytes( $length );
			$encoded = Base64url::encode( $data );

			$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]*$/', $encoded );
			$this->assertSame( $data, Base64url::decode( $encoded ) );
		}
	}

	public function test_uses_url_safe_alphabet() {
		$this->assertSame( '-_-_', Base64url::encode( "\xfb\xff\xbf" ) );
		$this->assertSame( "\xfb\xff\xbf", Base64url::decode( '-_-_' ) );
	}

	public function test_invalid_characters_return_null() {
		$this->assertNull( Base64url::decode( 'ab+c' ) );
		$this->assertNull( Base64url::decode( 'ab/c' ) );
		$this->assertNull( Base64url::decode( 'ab c' ) );
		$this->assertNull( Base64url::decode( 'a*b' ) );
		$this->assertNull( Base64url::decode( 'a=bc' ) );
	}

	public function test_trailing_newline_returns_null() {
		$this->assertNull( Base64url::decode( "YWJj\n" ) );
	}

	public function test_padding_is_accepted() {
		$this->assertSame( 'a', Base64url::decode( 'YQ==' ) );
		$this->assertSame( 'a', Base64url::decode( 'YQ' ) );
		$this->assertSame( 'ab', Base64url::decode( 'YWI=' ) );
	}

	public function test_empty_string() {
		$this->assertSame( '', Base64url::encode( '' ) );
		$this->assertSame( '', Base64url::decode( '' ) );
	}
}
