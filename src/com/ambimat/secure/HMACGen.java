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
 * The Class HMACGen.
 */
public class HMACGen {
	 
	    /** The Constant IPAD. */
    	// HMAC configurations
	    private static final byte IPAD = 0x36; // Inner padding byte
	    
    	/** The Constant OPAD. */
    	private static final byte OPAD = 0x5C; // Outer padding byte

	    /** The Constant KEY_SIZE_HMAC1. */
    	// HMAC configurations
	    private static final byte KEY_SIZE_HMAC1 = 8;
	    
    	/** The Constant HMAC_SIZE_HMAC1. */
    	private static final byte HMAC_SIZE_HMAC1 = 20;

	    /** The Constant KEY_SIZE_HMAC256. */
    	private static final byte KEY_SIZE_HMAC256 = 8;
	    
    	/** The Constant HMAC_SIZE_HMAC256. */
    	private static final byte HMAC_SIZE_HMAC256 = 32;

	    /** The Constant KEY_SIZE_HMAC512. */
    	private static final byte KEY_SIZE_HMAC512 = 16;
	    
    	/** The Constant HMAC_SIZE_HMAC512. */
    	private static final byte HMAC_SIZE_HMAC512 = 64;

	    /** The key 1. */
    	private byte[] key1;
	    
    	/** The key 256. */
    	private byte[] key256;
	    
    	/** The key 512. */
    	private byte[] key512;
	    
    	/** The sha 256. */
    	private MessageDigest sha256;
	    
    	/** The sha 1. */
    	private MessageDigest sha1;
	    
    	/** The sha 512. */
    	private MessageDigest sha512;
	    
    	/** The inner key pad. */
    	private byte[] innerKeyPad;
	    
    	/** The outer key pad. */
    	private byte[] outerKeyPad;
	    
    	/** The inner hash. */
    	private byte[] innerHash;
	    
    	/** The hmac. */
    	private byte[] hmac;
		
		/** The Constant SHA_1. */
		private static final byte SHA_1 = (byte) 0x01;

		/** The Constant SHA_256. */
		private static final byte SHA_256 = (byte) 0x02;

		/** The Constant SHA_512. */
		private static final byte SHA_512 = (byte) 0x03;

    
    /**
     * Initialize.
     */
    public void initialize(){
    	key1 = new byte[KEY_SIZE_HMAC1];
    	key256 = new byte[KEY_SIZE_HMAC256];
    	key512 = new byte[KEY_SIZE_HMAC512];
        sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        innerKeyPad = JCSystem.makeTransientByteArray(KEY_SIZE_HMAC512, JCSystem.CLEAR_ON_DESELECT);
        outerKeyPad = JCSystem.makeTransientByteArray(KEY_SIZE_HMAC512, JCSystem.CLEAR_ON_DESELECT);
        innerHash = JCSystem.makeTransientByteArray(HMAC_SIZE_HMAC512, JCSystem.CLEAR_ON_DESELECT);
        hmac = JCSystem.makeTransientByteArray(HMAC_SIZE_HMAC512, JCSystem.CLEAR_ON_DESELECT);


    }
    
    /**
     * Sets the key.
     *
     * @param buff the buff
     * @param keyLength the key length
     */
    public void setKey(byte[] buff, short keyLength) {
        if (keyLength != KEY_SIZE_HMAC1 && keyLength != KEY_SIZE_HMAC256 && keyLength != KEY_SIZE_HMAC512) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        switch (buff[ISO7816.OFFSET_P1]) {
		case SHA_1:// SHA1
			 Util.arrayCopyNonAtomic(buff, ISO7816.OFFSET_CDATA, key1, (short) 0, keyLength);
			break;
		case SHA_256:// SHA 256
			 Util.arrayCopyNonAtomic(buff, ISO7816.OFFSET_CDATA, key256, (short) 0, keyLength);
			break;
		case SHA_512:// SHA 512
			 Util.arrayCopyNonAtomic(buff, ISO7816.OFFSET_CDATA, key512, (short) 0, keyLength);
			break;
		}

    
    }
    
    /**
     * Generate HMAC.
     *
     * @param message the message
     * @param messageLength the message length
     * @param apdu the apdu
     * @param buff the buff
     */
    public void generateHMAC(byte[] message, short messageLength,APDU apdu,byte[] buff) {
        byte[] currentKey;
        byte hmacSize;

        byte p1=buff[ISO7816.OFFSET_P1];
        MessageDigest sha;
        // Determine HMAC size based on key size
        switch (p1) {
        case (byte) 0x01:// SHA1
                currentKey = key1;
                hmacSize = HMAC_SIZE_HMAC1;
                sha=sha1;
                break;
        case (byte) 0x02:// SHA 256
                currentKey = key256;
                hmacSize = HMAC_SIZE_HMAC256;
                sha=sha256;
                break;
        case (byte) 0x03:// SHA 512
                currentKey = key512;
                hmacSize = HMAC_SIZE_HMAC512;
                sha=sha512;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
        }
        
    

        // Perform HMAC calculation

        // Create inner and outer padded keys
        for (short i = 0; i < currentKey.length; i++) {
            innerKeyPad[i] = (byte) (currentKey[i] ^ IPAD);
            outerKeyPad[i] = (byte) (currentKey[i] ^ OPAD);
        }

        // Calculate inner hash
        sha.reset();
        sha.update(innerKeyPad, (short) 0, (short) innerKeyPad.length);
        short innerHashLength = sha.doFinal(innerHash, (short) 0, (short) innerHash.length, innerHash, (short) 0);

        // Calculate outer hash

        sha.reset();
        sha.update(outerKeyPad, (short) 0, (short) outerKeyPad.length);
        sha.update(innerHash, (short) 0, innerHashLength);
        short hmacLength = sha.doFinal(innerHash, (short) 0, innerHashLength, hmac, (short) 0);
        
        Util.arrayCopyNonAtomic(hmac, (short)0, buff, (short)0, hmacLength);
        // Return the HMAC as the response
        apdu.setOutgoingAndSend((short)0, hmacLength);
    }

}
