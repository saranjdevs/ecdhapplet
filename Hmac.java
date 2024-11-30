/*
 * 
 */
package com.ambimat.secure;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

// TODO: Auto-generated Javadoc
/**
 * The Class Hmac.
 */
public class Hmac {

	/** The Constant SHA_1. */
	private static final byte SHA_1 = (byte) 0x01;

	/** The Constant SHA_256. */
	private static final byte SHA_256 = (byte) 0x02;

	/** The Constant SHA_512. */
	private static final byte SHA_512 = (byte) 0x03;

	/** The Constant SHA_1_256_LENGTH. */
	private static final byte SHA_1_256_LENGTH = (byte) 0x08;

	/** The Constant SHA_512_LENGTH. */
	private static final byte SHA_512_LENGTH = (byte) 0x10;

	/** The default offset. */
	private final short DEFAULT_OFFSET = 0;
	/** The m session MAC 256. */
	Signature m_sessionMAC256 = null;

	/** The m session MAC 1. */
	Signature m_sessionMAC1 = null;

	/** The m session MAC 512. */
	Signature m_sessionMAC512 = null;

	/** The key type 256. */
	HMACKey keyType256 = null;

	/** The key type 1. */
	HMACKey keyType1 = null;

	/** The key type 512. */
	HMACKey keyType512 = null;

	/**
	 * Initalize.
	 */
	public void initalize() {
		m_sessionMAC256 = Signature.getInstance(Signature.ALG_HMAC_SHA_256,
				false);
		m_sessionMAC1 = Signature.getInstance(Signature.ALG_HMAC_SHA1, false);
		m_sessionMAC512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512,
				false);

		// Create HMAC Key Used in Mac
		keyType256 = (HMACKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
		keyType1 = (HMACKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_HMAC_SHA_1_BLOCK_64,// 64
				false);
		keyType512 = (HMACKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);

	}

	/**
	 * Sets the hmac key.
	 * 
	 * @param buff
	 *            the buff
	 * @param len
	 *            the len
	 * @param apdu
	 *            the apdu
	 */
	public void setHmacKey(byte[] buff, short len, APDU apdu) {

		switch (buff[ISO7816.OFFSET_P1]) {
		case SHA_1:// SHA1
			if (buff[ISO7816.OFFSET_LC] != SHA_1_256_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			keyType1.setKey(buff, DEFAULT_OFFSET, (short) len);
			break;
		case SHA_256:// SHA 256
			if (buff[ISO7816.OFFSET_LC] != SHA_1_256_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			keyType256.setKey(buff, DEFAULT_OFFSET, (short) len);
			break;
		case SHA_512:// SHA 512
			if (buff[ISO7816.OFFSET_LC] != SHA_512_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			keyType512.setKey(buff, DEFAULT_OFFSET, (short) len);
			break;
		}

	}

	/**
	 * Calculate hmac.
	 * 
	 * @param buff
	 *            the buff
	 * @param len
	 *            the len
	 * @param apdu
	 *            the apdu
	 */
	public void calculateHmac(byte[] buff, short len, APDU apdu) {
		HMACKey key = null;
		Signature hmacSign = null;
		byte p1 = buff[ISO7816.OFFSET_P1];
		byte p2 = buff[ISO7816.OFFSET_P2];
		if (!(p1 >= (byte) 0x01 && p1 <= (byte) 0x03)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		if (!(len >= (byte) 0x01 && len <= (byte) 0x7F)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		switch (p1) {
		case (byte) 0x01:// SHA1
			key = keyType1;
			hmacSign = m_sessionMAC1;

			break;
		case (byte) 0x02:// SHA 256
			key = keyType256;
			hmacSign = m_sessionMAC256;
			break;
		case (byte) 0x03:// SHA 512
			key = keyType512;
			hmacSign = m_sessionMAC512;
			break;
		}

		hmacSign.init(key, Signature.MODE_SIGN);
		short macLength = hmacSign.sign(buff, ISO7816.OFFSET_CDATA, len, buff,
				(short) 0);

		apdu.setOutgoingAndSend((short) 0, macLength);
		// TODO Auto-generated method stub

	}

}
