/*
 * 
 */
package com.ambimat.secure;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.InitializedMessageDigest;
import javacard.security.MessageDigest;

// TODO: Auto-generated Javadoc
/**
 * The Class Hash.
 */
public class Hash {
	
	/** The Constant SHA_1. */
	private static final byte SHA_1 = 0;
	
	/** The Constant SHA_256. */
	private static final byte SHA_256 = 1;
	
	/** The Constant SHA_512. */
	private static final byte SHA_512 = 2;
	
	/** The default offset. */
	private final short DEFAULT_OFFSET = 0;
	
	/** The sha 1. */
	private InitializedMessageDigest sha1;
	
	/** The sha 256. */
	private InitializedMessageDigest sha256;
	
	/** The sha 512. */
	private InitializedMessageDigest sha512;

	/**
	 * Initialize.
	 */
	public void initialize() {
		// Creates a InitializedMessageDigest object instance of the ALG_SHA
		// algorithm.
		sha1 = MessageDigest.getInitializedMessageDigestInstance(
				MessageDigest.ALG_SHA, false);
		// Creates a InitializedMessageDigest object instance of the ALG_SHA_256
		// algorithm.
		sha256 = MessageDigest.getInitializedMessageDigestInstance(
				MessageDigest.ALG_SHA_256, false);
		// Creates a InitializedMessageDigest object instance of the ALG_SHA_512
		// algorithm.
		sha512 = MessageDigest.getInitializedMessageDigestInstance(
				MessageDigest.ALG_SHA_512, false);
	}

	/**
	 * Generate hash.
	 *
	 * @param buffer the buffer
	 * @param apdu the apdu
	 * @param len the len
	 */
	public void generateHash(byte[] buffer, APDU apdu, short len) {
		InitializedMessageDigest hash = null;
		short offset = ISO7816.OFFSET_CDATA;
		switch (buffer[ISO7816.OFFSET_P1] & 0x7f) {
		case SHA_1:
			hash = sha1;
			break;
		case SHA_256:
			hash = sha256;
			break;
		case SHA_512:
			hash = sha512;

			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}

		if (hash == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		// Reset the MessageDigest object to the initial state.
		hash.reset();
		// Generate a hash of all the input data.
		short ret = hash.doFinal(buffer, offset, len, buffer, DEFAULT_OFFSET);
		apdu.setOutgoingAndSend(DEFAULT_OFFSET, ret);

	}

}
