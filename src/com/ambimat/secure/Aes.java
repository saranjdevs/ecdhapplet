/*
 * 
 */
package com.ambimat.secure;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

// TODO: Auto-generated Javadoc
/**
 * The Class Aes.
 */
public class Aes {

	/** The Constant AES_128. */
	private final byte AES_128 = (byte) 0x01;
	
	/** The Constant AES_192. */
	private  final byte AES_192 = (byte) 0x02;
	
	/** The Constant AES_256. */
	private  final byte AES_256 = (byte) 0x03;
	
	/** The length 24. */
	private final byte LENGTH_24 = 24;
	
	/** The length 32. */
	private final byte LENGTH_32 = 32;
	
	/** The length 16. */
	private final byte LENGTH_16 = 16;
	
	/** The default offset. */
	private final short DEFAULT_OFFSET = 0;
	
	/** The default value. */
	private static byte DEFAULT_VALUE = 0;

	/** The aes key len. */
	private byte aesKeyLen;
	
	/** The aes key. */
	private byte[] aesKey;
	
	/** The aes ICV. */
	private byte[] aesICV;

	/** The aes ecb cipher. */
	private Cipher aesEcbCipher;
	
	/** The aes cbc cipher. */
	private Cipher aesCbcCipher;

	/** The temp aes key 1. */
	private Key tempAesKey1;
	
	/** The temp aes key 2. */
	private Key tempAesKey2;
	
	/** The temp aes key 3. */
	private Key tempAesKey3;

	/**
	 * Initalize.
	 */
	public void initalize() {
		// AES DATA
		aesKey = new byte[LENGTH_32];
		aesICV = new byte[LENGTH_16];
		// AES CBC is set aS 00...00 by default otherwise use the command to set
		// ICV
		Util.arrayFillNonAtomic(aesICV, DEFAULT_OFFSET, LENGTH_16,
				DEFAULT_VALUE);
		aesKeyLen = DEFAULT_VALUE;
		// Create a AES ECB/CBS object instance of the AES algorithm.
		aesEcbCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
				false);
		aesCbcCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
				false);
		// Create uninitialized cryptographic keys for AES algorithms
		tempAesKey1 = KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_128, false);
		tempAesKey2 = KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_192, false);
		tempAesKey3 = KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_256, false);

	}

	/**
	 * Sets the aes key.
	 *
	 * @param apdu the apdu
	 * @param len the len
	 */
	public void setAesKey(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		byte keyLen = DEFAULT_VALUE;
		switch (buffer[ISO7816.OFFSET_P1]) {
		case AES_128:
			if (len != LENGTH_16) // The length of key is 16 bytes
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			keyLen = LENGTH_16;
			break;
		case AES_192:
			if (len != LENGTH_24) // The length of key is 24 bytes
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			keyLen = LENGTH_24;
			break;
		case AES_256:
			if (len != LENGTH_32) // The length of key is 32 bytes
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			keyLen = LENGTH_32;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}

		JCSystem.beginTransaction();
		// Copy the incoming AES Key value to the global variable 'aesKey'
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, aesKey, DEFAULT_OFFSET,
				len);
		aesKeyLen = keyLen;
		JCSystem.commitTransaction();
	}

	/**
	 * Sets the aes ICV.
	 *
	 * @param apdu the apdu
	 * @param len the len
	 */
	// Set AES ICV, ICV is the initial vector
	public void setAesICV(APDU apdu, short len) {
		if (len != LENGTH_16) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// Copy the incoming ICV value to the global variable 'aesICV'
		Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, aesICV,
				DEFAULT_OFFSET, LENGTH_16);
	}

	// Sets the Key data, and return the AESKey object. The plaintext length of
	/**
	 * Gets the aes key.
	 *
	 * @return the aes key
	 */
	// input key data is 16/24/32 bytes.
	private Key getAesKey() {
		Key tempAesKey = null;
		switch (aesKeyLen) {
		case LENGTH_16:
			tempAesKey = tempAesKey1;
			break;
		case LENGTH_24:
			tempAesKey = tempAesKey2;
			break;
		case LENGTH_32:
			tempAesKey = tempAesKey3;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			break;
		}
		// Set the 'aesKey' key data value into the internal representation
		((AESKey) tempAesKey).setKey(aesKey, DEFAULT_OFFSET);
		return tempAesKey;
	}

	/**
	 * Do aes cipher de cipher.
	 *
	 * @param buffer the buffer
	 * @param apdu the apdu
	 * @param len the len
	 */
	// AES algorithm encrypt and decrypt
	public void doAesCipherDeCipher(byte[] buffer, APDU apdu, short len) {
		// The byte length to be encrypted/decrypted must be a multiple of 16
		if (len <= DEFAULT_VALUE || len % LENGTH_16 != 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		Key key = getAesKey();
		byte mode = buffer[ISO7816.OFFSET_P1] == DEFAULT_VALUE ? Cipher.MODE_ENCRYPT
				: Cipher.MODE_DECRYPT;
		Cipher cipher = buffer[ISO7816.OFFSET_P2] == DEFAULT_VALUE ? aesEcbCipher
				: aesCbcCipher;
		// Initializes the 'cipher' object with the appropriate Key and
		// algorithm specific parameters.
		// AES algorithms in CBC mode expect a 16-byte parameter value for the
		// initial vector(IV)
		if (cipher == aesCbcCipher) {
			cipher.init(key, mode, aesICV, DEFAULT_OFFSET, LENGTH_16);
		} else {
			cipher.init(key, mode);
		}
		// This method must be invoked to complete a cipher operation. Generates
		// encrypted/decrypted output from all/last input data.
		cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer,
				DEFAULT_OFFSET);
		apdu.setOutgoingAndSend(DEFAULT_OFFSET, len);
	}
}
