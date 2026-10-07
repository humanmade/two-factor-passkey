( function () {
	'use strict';

	function isSupported() {
		return !! ( window.PublicKeyCredential && navigator.credentials );
	}

	/** Decode a base64url string (no padding) to an ArrayBuffer. */
	function base64urlToBuffer( value ) {
		let base64 = String( value ).replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( base64.length % 4 ) {
			base64 += '=';
		}
		const binary = window.atob( base64 );
		const bytes = new Uint8Array( binary.length );
		for ( let i = 0; i < binary.length; i++ ) {
			bytes[ i ] = binary.charCodeAt( i );
		}
		return bytes.buffer;
	}

	/** Encode an ArrayBuffer or Uint8Array as base64url with no padding. */
	function bufferToBase64url( buffer ) {
		const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array( buffer );
		let binary = '';
		for ( let i = 0; i < bytes.length; i++ ) {
			binary += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function decodeDescriptors( list ) {
		return ( list || [] ).map( function ( descriptor ) {
			return Object.assign( {}, descriptor, { id: base64urlToBuffer( descriptor.id ) } );
		} );
	}

	function toCreationOptions( json ) {
		if ( typeof PublicKeyCredential !== 'undefined' && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' ) {
			try {
				return PublicKeyCredential.parseCreationOptionsFromJSON( json );
			} catch ( e ) {
				// Fall back to manual decoding.
			}
		}

		const options = Object.assign( {}, json );
		options.challenge = base64urlToBuffer( json.challenge );
		options.user = Object.assign( {}, json.user, { id: base64urlToBuffer( json.user.id ) } );
		if ( json.excludeCredentials ) {
			options.excludeCredentials = decodeDescriptors( json.excludeCredentials );
		}
		return options;
	}

	function toRequestOptions( json ) {
		if ( typeof PublicKeyCredential !== 'undefined' && typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' ) {
			try {
				return PublicKeyCredential.parseRequestOptionsFromJSON( json );
			} catch ( e ) {
				// Fall back to manual decoding.
			}
		}

		const options = Object.assign( {}, json );
		options.challenge = base64urlToBuffer( json.challenge );
		if ( json.allowCredentials ) {
			options.allowCredentials = decodeDescriptors( json.allowCredentials );
		}
		return options;
	}

	function credentialToJSON( credential ) {
		if ( typeof credential.toJSON === 'function' ) {
			return credential.toJSON();
		}

		const response = credential.response;
		const result = {
			id: credential.id,
			rawId: bufferToBase64url( credential.rawId ),
			type: credential.type,
			authenticatorAttachment: credential.authenticatorAttachment || null,
			clientExtensionResults: typeof credential.getClientExtensionResults === 'function' ? credential.getClientExtensionResults() : {},
			response: {
				clientDataJSON: bufferToBase64url( response.clientDataJSON ),
			},
		};

		if ( response.attestationObject ) {
			result.response.attestationObject = bufferToBase64url( response.attestationObject );
			result.response.transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
		} else {
			result.response.authenticatorData = bufferToBase64url( response.authenticatorData );
			result.response.signature = bufferToBase64url( response.signature );
			result.response.userHandle = response.userHandle ? bufferToBase64url( response.userHandle ) : null;
		}

		return result;
	}

	window.twoFactorPasskey = {
		isSupported: isSupported,
		toCreationOptions: toCreationOptions,
		toRequestOptions: toRequestOptions,
		credentialToJSON: credentialToJSON,
	};
}() );
