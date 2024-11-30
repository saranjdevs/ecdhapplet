/**
 * 
 */
package com.ambimat.secure;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.InitializedMessageDigest;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

// TODO: Auto-generated Javadoc
/**
 * The Class AmbiSecure.
 *
 * @author AnuragSharma
 */
public class AmbiSecure extends Applet implements ExtendedLength {

	/** The Constant MIN_LENGTH. */
	private static final byte MIN_LENGTH = (byte) 0x01;

	/** The Constant MAX_LENGTH. */
	private static final byte MAX_LENGTH = (byte) 0x7F;

	/** The ecdh. */
	Ecdh ecdh;
	
	/** The aes. */
	Aes aes;
	
	/** The hash. */
	Hash hash;
	
	/** The hmac. */
	//Hmac hmac;
	
	HMACGen hmacGen;
	
	/** The m rng random. */
	RandomData m_rngRandom;

	// ************************************** AES DATA
	/** The Constant INS_SET_AES_KEY. */
	// ***************************************************************
	private  final byte INS_SET_AES_KEY = (byte) 0x10;
	
	/** The Constant INS_SET_AES_ICV. */
	private  final byte INS_SET_AES_ICV = (byte) 0x11;
	
	/** The Constant INS_DO_AES_CIPHER. */
	private  final byte INS_DO_AES_CIPHER = (byte) 0x12;
	
	/** The ins gkp. */
	// ***************************************************************************************************************
	private final byte INS_GKP = (byte) 0xA0;
	
	/** The ins sign. */
	private final byte INS_SIGN = (byte) 0xA1;
	
	/** The ins gkp ecdh. */
	private final byte INS_GKP_ECDH = (byte) 0xA3;
	
	/** The ins gshs ecdh. */
	private final byte INS_GSHS_ECDH = (byte) 0xA4;
	
	/** The ins gen hash. */
	private final byte INS_GEN_HASH = (byte) 0xA6;
	
	/** The ins gen rand. */
	private final byte INS_GEN_RAND = (byte) 0xA7;

	/** The ins ecc verify input data. */
	private final byte INS_ECC_VERIFY_INPUT_DATA = (byte) 0x48;
	
	/** The ins ecc verify. */
	private final byte INS_ECC_VERIFY = (byte) 0x49;

	/** The ins set hmac key. */
	private final byte INS_SET_HMAC_KEY = (byte) 0xA8;
	
	/** The ins hmac. */
	private final byte INS_HMAC = (byte) 0xA9;

	/** The Constant TAG_PUBLIC_KEY. */
	private  final byte TAG_PUBLIC_KEY = (byte) 0xB0;
	
	/** The Constant TAG_SIGNED_DATA. */
	private  final byte TAG_SIGNED_DATA = (byte) 0xB1;
	
	/** The Constant TAG_GET_MASTER_KEY. */
	private  final byte TAG_GET_MASTER_KEY = (byte) 0xA2;
	
	/** The Constant TAG_SET_MASTER_KEY. */
	private  final byte TAG_SET_MASTER_KEY = (byte) 0xB2;
	

	// *****************************************************************************************************************

	/** The Constant MAX_S. */
	// ******************************************************************************************************************
	final  private byte[] MAX_S = { (byte) 0x7F, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x5D,
			(byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4,
			(byte) 0x50, (byte) 0x1D, (byte) 0xDF, (byte) 0xE9, (byte) 0x2F,
			(byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20, (byte) 0xA0 };
	
	/** The Constant S_SUB. */
	final  private byte[] S_SUB = { (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA,
			(byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48,
			(byte) 0xA0, (byte) 0x3B, (byte) 0xBF, (byte) 0xD2, (byte) 0x5E,
			(byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

	/** Constants for secp256k1 curve. */
	protected  final byte ECC_ICC_Prime[] = { (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC, (byte) 0x2F };
	
	/** The Constant ECC_ICC_A. */
	protected  final byte ECC_ICC_A[] = { (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
	
	/** The Constant ECC_ICC_B. */
	protected  final byte ECC_ICC_B[] = { (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07 };
	
	/** The Constant ECC_ICC_G. */
	protected  final byte ECC_ICC_G[] = { (byte) 0x04, (byte) 0x79,
			(byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9, (byte) 0xDC,
			(byte) 0xBB, (byte) 0xAC, (byte) 0x55, (byte) 0xA0, (byte) 0x62,
			(byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B, (byte) 0x07,
			(byte) 0x02, (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D,
			(byte) 0xCE, (byte) 0x28, (byte) 0xD9, (byte) 0x59, (byte) 0xF2,
			(byte) 0x81, (byte) 0x5B, (byte) 0x16, (byte) 0xF8, (byte) 0x17,
			(byte) 0x98, (byte) 0x48, (byte) 0x3A, (byte) 0xDA, (byte) 0x77,
			(byte) 0x26, (byte) 0xA3, (byte) 0xC4, (byte) 0x65, (byte) 0x5D,
			(byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11,
			(byte) 0x08, (byte) 0xA8, (byte) 0xFD, (byte) 0x17, (byte) 0xB4,
			(byte) 0x48, (byte) 0xA6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
			(byte) 0x9C, (byte) 0x47, (byte) 0xD0, (byte) 0x8F, (byte) 0xFB,
			(byte) 0x10, (byte) 0xD4, (byte) 0xB8 };
	
	/** The Constant ECC_ICC_R. */
	protected  final byte ECC_ICC_R[] = { (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA,
			(byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48,
			(byte) 0xA0, (byte) 0x3B, (byte) 0xBF, (byte) 0xD2, (byte) 0x5E,
			(byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };
	
	/** The Constant SECP256K1_K. */
	protected  final byte SECP256K1_K = (byte) 0x01;

	/** The Constant ERROR_APDU_EXCEPTION. */
	private  final short ERROR_APDU_EXCEPTION = 1;
	
	/** The default offset. */
	private final short DEFAULT_OFFSET = 0;
	
	/** The ecc ICC pub key. */
	private ECPublicKey eccICCPubKey = null;
	
	/** The ecc ICC priv key. */
	private ECPrivateKey eccICCPrivKey = null;
	
	/** The key pair ICC. */
	private KeyPair keyPairICC = null;

	/** The ecc signature. */
	private final Signature eccSignature;

	/** The new buff. */
	private byte[] newBuff = new byte[(short) (32767)];
	
	/** The copied data. */
	private short copiedData;
	
	/** The key. */
	private byte[] key = new byte[32];

	/**
	 * Install.
	 *
	 * @param bArray the b array
	 * @param bOffset the b offset
	 * @param bLength the b length
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new AmbiSecure().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	/**
	 * Instantiates a new ambi secure.
	 */
	public AmbiSecure() {
		try {
			eccICCPubKey = (ECPublicKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256,
					false);
			eccICCPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256,
					false);
			keyPairICC = new KeyPair(eccICCPubKey, eccICCPrivKey);

			eccSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256,
					false);
			// ECC ICC Public Key
			eccICCPubKey.setA(ECC_ICC_A, DEFAULT_OFFSET, (short) ECC_ICC_A.length);
			eccICCPubKey.setB(ECC_ICC_B, DEFAULT_OFFSET, (short) ECC_ICC_B.length);
			eccICCPubKey.setFieldFP(ECC_ICC_Prime, (short) (short) 0,
					(short) ECC_ICC_Prime.length);
			eccICCPubKey.setG(ECC_ICC_G, DEFAULT_OFFSET, (short) ECC_ICC_G.length);
			eccICCPubKey.setR(ECC_ICC_R, DEFAULT_OFFSET, (short) ECC_ICC_R.length);
			eccICCPubKey.setK(SECP256K1_K);

			// ECC ICC Private Key
			eccICCPrivKey.setFieldFP(ECC_ICC_Prime, DEFAULT_OFFSET,
					(short) ECC_ICC_Prime.length);
			eccICCPrivKey.setA(ECC_ICC_A, DEFAULT_OFFSET, (short) ECC_ICC_A.length);
			eccICCPrivKey.setB(ECC_ICC_B, DEFAULT_OFFSET, (short) ECC_ICC_B.length);
			eccICCPrivKey.setG(ECC_ICC_G, DEFAULT_OFFSET, (short) ECC_ICC_G.length);
			eccICCPrivKey.setR(ECC_ICC_R, DEFAULT_OFFSET, (short) ECC_ICC_R.length);
			eccICCPrivKey.setK(SECP256K1_K);

			ecdh = new Ecdh();
			ecdh.initializeEcdh();
			aes = new Aes();
			aes.initalize();
			hash = new Hash();
			hash.initialize();
			//hmac = new Hmac();
			//hmac.initalize();
			hmacGen=new HMACGen();
			hmacGen.initialize();
			JCSystem.requestObjectDeletion();
		} catch (CryptoException ex) {
			throw (ex);
		}
	}

	/* (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			copiedData = 0;
			return;
		}

		try {
			byte[] buff = apdu.getBuffer();
			short length = 0;
			short len = 0;
			byte slot = 0;
			switch (buff[ISO7816.OFFSET_INS]) {

			case INS_SET_AES_KEY:
				len = apdu.setIncomingAndReceive();
				// SET_AES_KEY
				aes.setAesKey(apdu, len);
				break;
			case INS_SET_AES_ICV:
				// SET_AES_ICV
				len = apdu.setIncomingAndReceive();
				aes.setAesICV(apdu, len);
				break;
			case INS_DO_AES_CIPHER:
				len = apdu.setIncomingAndReceive();
				// DO_AES_CIPHER
				aes.doAesCipherDeCipher(buff, apdu, len);
				break;
			case INS_GEN_RAND:
				if (buff[ISO7816.OFFSET_LC] != (byte) 0x01) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				if (buff[ISO7816.OFFSET_CDATA] >= MIN_LENGTH
						&& buff[ISO7816.OFFSET_CDATA] <= MAX_LENGTH) {
					length = buff[ISO7816.OFFSET_CDATA];
					doRandom(buff, apdu, length);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}

				break;
			case INS_GKP:
				apdu.setIncomingAndReceive();
				slot = buff[ISO7816.OFFSET_P1];
				len = processGenKeyPair(buff, slot);
				apdu.setOutgoingAndSend(DEFAULT_OFFSET, (len));
				break;

			case INS_GKP_ECDH:
				apdu.setIncomingAndReceive();
				slot = buff[ISO7816.OFFSET_P1];
				len = ecdh.processGenKeyPairEcdh(buff, slot);
				apdu.setOutgoingAndSend(DEFAULT_OFFSET, len);
				break;

			case INS_GSHS_ECDH:
				apdu.setIncomingAndReceive();
				short off = ISO7816.OFFSET_CDATA;
				short pubkeyTag = (short) (0x00FF & buff[off]);
				if (pubkeyTag != (short) (0x00FF & 0xB0)) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				off++;
				short lenPubKey = buff[off];
				if (lenPubKey != (short) (0x00FF & 0x41)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				off++;
				Util.arrayCopyNonAtomic(buff, (short) off, newBuff,DEFAULT_OFFSET,
						lenPubKey);

				short lenShs = ecdh.generateSecret(newBuff,DEFAULT_OFFSET,
						lenPubKey, buff, DEFAULT_OFFSET);
				apdu.setOutgoingAndSend(DEFAULT_OFFSET, (lenShs));
				break;

			case INS_SIGN:
				signorStoreData(apdu, buff, true);
				break;

			case INS_ECC_VERIFY_INPUT_DATA:
				signorStoreData(apdu, buff, false);
				break;

			case INS_ECC_VERIFY:
				apdu.setIncomingAndReceive();
				short signaturelength = apdu.getIncomingLength();
				boolean ret = eccVerify(buff, ISO7816.OFFSET_CDATA,
						signaturelength);
				buff[(short) 0] = ret ? (byte) 1 : (byte) 0;
				apdu.setOutgoingAndSend((short) 0, (short) 1);
				break;

			case TAG_SET_MASTER_KEY:
				length = apdu.setIncomingAndReceive();
				Util.arrayCopy(buff, ISO7816.OFFSET_CDATA, key, (byte) 0,
						length);

				break;
			case TAG_GET_MASTER_KEY:

				Util.arrayCopy(key, (byte) 0, buff, (byte) 2, (byte) key.length);
				buff[0] = TAG_GET_MASTER_KEY;
				buff[1] = (byte) key.length;
				apdu.setOutgoingAndSend((byte) 0, (byte) (key.length + 2));

				break;

			case INS_GEN_HASH:
				len = apdu.setIncomingAndReceive();
				if (len >= (byte) 0x01 && len <= (byte) 0x7F) {
					hash.generateHash(buff, apdu, len);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				break;

			case INS_SET_HMAC_KEY:
				len = apdu.setIncomingAndReceive();
				hmacGen.setKey(buff, len);
				break;
			case INS_HMAC:
				len = apdu.setIncomingAndReceive();
				hmacGen.generateHMAC(buff, len, apdu, buff);
				break;
			default:
				// good practice: If you don't know the INStruction, say so:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} catch (APDUException e) {
			ISOException.throwIt(ERROR_APDU_EXCEPTION);
		} finally {

		}
	}

	/**
	 * Signor store data.
	 *
	 * @param apdu the apdu
	 * @param buff the buff
	 * @param toSign the to sign
	 */
	private void signorStoreData(APDU apdu, byte[] buff, boolean toSign) {
		short length = apdu.setIncomingAndReceive();

		short totallen = apdu.getIncomingLength();
		byte slot = buff[ISO7816.OFFSET_P1];
		byte isLast = buff[ISO7816.OFFSET_P2];
		short len = 0;
		short dataOffset = apdu.getOffsetCdata();
		boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);
		if (extendedLength) {
			while ((copiedData < totallen) && extendedLength) {
				copiedData = Util.arrayCopyNonAtomic(buff, (short) dataOffset,
						newBuff, (short) copiedData, (short) (length));
				if (copiedData < totallen) {
					dataOffset = 0;
					len = apdu.receiveBytes((short) 0); // receive the
					// next
				}
			}
			if (toSign) {
				len = eccSign(newBuff, (byte) 0, buff, (byte) 2, slot, totallen);
				apdu.setOutgoingAndSend((short) 0, (len));
			}
			return;
		} else {
			copiedData = Util.arrayCopyNonAtomic(buff, (short) dataOffset,
					newBuff, (short) copiedData, (short) (length));
		}
		if (isLast == (byte) 0x80) {
			if (toSign) {
				len = eccSign(newBuff, (byte) 0, buff, (byte) 2, slot,
						copiedData);
				apdu.setOutgoingAndSend((short) 0, (len));
			}
			return;
		}

	}

	/**
	 * Sings data.
	 *
	 * @param inBuff            - input buffer containing data to be signed
	 * @param inOff            - offset from where data starts in {@link}inBuff
	 * @param outBuff            - output buffer where signature will be stored
	 * @param outOff            - offset from where output data starts
	 * @param slot            - slot to be used
	 * @param len            - length of data to be signed
	 * @return signed data length
	 */
	public short eccSign(byte[] inBuff, short inOff, byte[] outBuff,
			short outOff, byte slot, short len) {
		eccSignature.init(eccICCPrivKey, Signature.MODE_SIGN);
		short length = 0;
		length = eccSignature.sign(inBuff, inOff, len, outBuff, outOff);
		// length = eccSignature.signPreComputedHash(inBuff, inOff, len,
		// outBuff, outOff);
		outBuff[0] = TAG_SIGNED_DATA;
		outBuff[1] = (byte) (length);
		// outBuff[2] = (byte) slot;
		return (short) (length + 2);
	}

	/**
	 * Generates Key pair.
	 *
	 * @param apduBuffer the apdu buffer
	 * @param slot the slot
	 * @return the short
	 */
	private short processGenKeyPair(byte[] apduBuffer, byte slot) {

		short len1 = 0;

		// Generate ECC Key Pair
		keyPairICC.genKeyPair();
		eccICCPrivKey = (ECPrivateKey) keyPairICC.getPrivate();
		eccICCPubKey = (ECPublicKey) keyPairICC.getPublic();
		len1 = eccICCPubKey.getW(apduBuffer, (short) 2);
		apduBuffer[0] = TAG_PUBLIC_KEY;
		apduBuffer[1] = (byte) (len1);
		// apduBuffer[2] = (byte) slot;

		// len2 = eccICCPrivKey.getS(apduBuffer, (byte) (5 + len1));

		return (short) (len1 + 2);
	}

	// Verify the ECC signature, the format of APDU data field is : the
	/**
	 * Ecc verify.
	 *
	 * @param signature the signature
	 * @param signOff the sign off
	 * @param sigLen the sig len
	 * @return true, if successful
	 */
	// signature data and the data to be verified
	private boolean eccVerify(byte[] signature, short signOff, short sigLen) {

		// Sets the point of the curve comprising the public key.

		// Initializes the Signature object with the appropriate Key
		eccSignature.init(keyPairICC.getPublic(), Signature.MODE_VERIFY);
		// Verify the signature of input data against the passed in ECC
		// signature.
		boolean ret = eccSignature.verify(newBuff, (short) 0, copiedData,
				signature, signOff, sigLen);
		return ret;
		// buffer[(short)0] = ret ? (byte)1 : (byte)0;
		// apdu.setOutgoingAndSend((short)0, (short)1);
	}

	// ************************************************* AES Logic
	// *******************************************************
	// Set the key of AES Encrypt/Decrypt

	// Generate Hash

	/**
	 * Do random.
	 *
	 * @param buffer the buffer
	 * @param apdu the apdu
	 * @param length the length
	 */
	private void doRandom(byte[] buffer, APDU apdu, short length) {

		m_rngRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		m_rngRandom.generateData(buffer, (short) 0, (short) (0x00FF & length));
		apdu.setOutgoingAndSend((short) 0, (short) (0x00FF & length));

	}
}
