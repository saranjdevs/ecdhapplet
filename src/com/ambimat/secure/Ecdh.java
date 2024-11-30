/*
 * 
 */
package com.ambimat.secure;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

// TODO: Auto-generated Javadoc
/**
 * The Class Ecdh.
 */
public class Ecdh {
	
	/** The nistp 256 p. */
	final byte[] nistp256_p = { (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1,
			(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
			(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
			(byte) 0x0, (byte) 0x0, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
	
	/** The nistp 256 a. */
	final byte[] nistp256_a = { (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1,
			(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
			(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
			(byte) 0x0, (byte) 0x0, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc };
	
	/** The nistp 256 b. */
	final byte[] nistp256_b = { (byte) 0x5a, (byte) 0xc6, (byte) 0x35,
			(byte) 0xd8, (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7,
			(byte) 0xb3, (byte) 0xeb, (byte) 0xbd, (byte) 0x55, (byte) 0x76,
			(byte) 0x98, (byte) 0x86, (byte) 0xbc, (byte) 0x65, (byte) 0x1d,
			(byte) 0x6, (byte) 0xb0, (byte) 0xcc, (byte) 0x53, (byte) 0xb0,
			(byte) 0xf6, (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e,
			(byte) 0x27, (byte) 0xd2, (byte) 0x60, (byte) 0x4b };
	
	/** The nistp 256 R. */
	final byte[] nistp256_R = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6,
			(byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E,
			(byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2,
			(byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51 };
	
	/** The nistp 256 G. */
	final byte[] nistp256_G = { (byte) 0x4, (byte) 0x6b, (byte) 0x17,
			(byte) 0xd1, (byte) 0xf2, (byte) 0xe1, (byte) 0x2c, (byte) 0x42,
			(byte) 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5,
			(byte) 0x63, (byte) 0xa4, (byte) 0x40, (byte) 0xf2, (byte) 0x77,
			(byte) 0x3, (byte) 0x7d, (byte) 0x81, (byte) 0x2d, (byte) 0xeb,
			(byte) 0x33, (byte) 0xa0, (byte) 0xf4, (byte) 0xa1, (byte) 0x39,
			(byte) 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96,
			(byte) 0x4f, (byte) 0xe3, (byte) 0x42, (byte) 0xe2, (byte) 0xfe,
			(byte) 0x1a, (byte) 0x7f, (byte) 0x9b, (byte) 0x8e, (byte) 0xe7,
			(byte) 0xeb, (byte) 0x4a, (byte) 0x7c, (byte) 0xf, (byte) 0x9e,
			(byte) 0x16, (byte) 0x2b, (byte) 0xce, (byte) 0x33, (byte) 0x57,
			(byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce, (byte) 0xcb,
			(byte) 0xb6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xbf,
			(byte) 0x51, (byte) 0xf5 };
	
	/** The ecdh key pair. */
	private KeyPair ecdhKeyPair = null;
	
	/** The ecdh ICC pub key. */
	private ECPublicKey ecdhICCPubKey = null;
	
	/** The ecdh ICC priv key. */
	public ECPrivateKey ecdhICCPrivKey = null;
	
	/** The ecdh sha. */
	private KeyAgreement ecdhSha = null;

	/** The Constant TAG_PUBLIC_KEY. */
	private static final byte TAG_PUBLIC_KEY = (byte) 0xB0;

	/** The Constant KEY_LENGTH. */
	private static final short KEY_LENGTH = (short) 256;

	/** The default offset. */
	private final short DEFAULT_OFFSET = 0;
	/**
	 * Initialize ecdh.
	 */
	public void initializeEcdh() {
		ecdhICCPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
		ecdhICCPubKey = (ECPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
		ecdhKeyPair = new KeyPair((PublicKey) ecdhICCPubKey,
				(PrivateKey) ecdhICCPrivKey);
		ecdhICCPubKey.setFieldFP(nistp256_p, DEFAULT_OFFSET,
				(short) (nistp256_p.length));
		ecdhICCPubKey.setA(nistp256_a, DEFAULT_OFFSET, (short) (nistp256_a.length));
		ecdhICCPubKey.setB(nistp256_b, DEFAULT_OFFSET, (short) (nistp256_b.length));
		ecdhICCPubKey.setG(nistp256_G, DEFAULT_OFFSET, (short) (nistp256_G.length));
		ecdhICCPubKey.setR(nistp256_R, DEFAULT_OFFSET, (short) (nistp256_R.length));

		ecdhICCPrivKey.setFieldFP(nistp256_p, DEFAULT_OFFSET,
				(short) (nistp256_p.length));
		ecdhICCPrivKey.setA(nistp256_a, DEFAULT_OFFSET, (short) (nistp256_a.length));
		ecdhICCPrivKey.setB(nistp256_b, DEFAULT_OFFSET, (short) (nistp256_b.length));
		ecdhICCPrivKey.setG(nistp256_G, DEFAULT_OFFSET, (short) (nistp256_G.length));
		ecdhICCPrivKey.setR(nistp256_R, DEFAULT_OFFSET, (short) (nistp256_R.length));
		ecdhSha = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);

	}

	/**
	 * Process gen key pair ecdh.
	 *
	 * @param apduBuffer the apdu buffer
	 * @param slot the slot
	 * @return the short
	 */
	public short processGenKeyPairEcdh(byte[] apduBuffer, byte slot) {

		short len1 = DEFAULT_OFFSET;
		try {
			ecdhKeyPair.genKeyPair();
			// Generate ECC Key Pair
			ecdhICCPrivKey = (ECPrivateKey) ecdhKeyPair.getPrivate();
			ecdhICCPubKey = (ECPublicKey) ecdhKeyPair.getPublic();
			len1 = ecdhICCPubKey.getW(apduBuffer, (short) 2);
			apduBuffer[0] = TAG_PUBLIC_KEY;
			apduBuffer[1] = (byte) (len1);

		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
		return (short) (len1 + 2);
	}

	/**
	 * Generate secret.
	 *
	 * @param publicData the public data
	 * @param publicOffset the public offset
	 * @param publicLength the public length
	 * @param apduBuffer the apdu buffer
	 * @param secretOffset the secret offset
	 * @return the short
	 */
	public short generateSecret(byte[] publicData, short publicOffset,
			short publicLength, byte[] apduBuffer, short secretOffset) {
		ecdhSha.init(ecdhICCPrivKey);
		short cLen = ecdhSha.generateSecret(publicData, publicOffset,
				publicLength, apduBuffer, secretOffset);

		return cLen;

	}

}
