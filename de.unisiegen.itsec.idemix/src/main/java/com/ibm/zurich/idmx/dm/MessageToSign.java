/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Abstraction for messages to be signed in Fiat-Shamir hash.
 */
public class MessageToSign {

    /** Message to be included in the Fiat-Shamit heuristic. */
    private final String message;

    /**
     * Constructor.
     * 
     * @param theMessage
     *            Message.
     */
    public MessageToSign(final String theMessage) {
        message = theMessage;
    }

    /**
     * @return Message.
     */
    public final byte[] getBytes() {
        return message.getBytes();
    }

    /**
     * @return Message.
     */
    public final String getMessage() {
        return message;
    }

    /**
     * Computes a hash over message type and message content.
     * 
     * @param sp
     *            The system parameters.
     * @return Hash value.
     * 
     * @see Utils#DIGEST_METHOD
     * @see MessageDigest
     */
    public final BigInteger getHash(final SystemParameters sp) {
        int hashLen = sp.getL_H() / Constants.BIT_PER_BYTE;
        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(Utils.DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            throw new RuntimeException(e1.getMessage());
        }

        byte[] msg = getBytes();
        digest.update(msg, 0, msg.length);

        final byte[] byteArray = new byte[hashLen];
        try {
            digest.digest(byteArray, 0, hashLen);
        } catch (Exception e) {
            throw new RuntimeException("Digest error (" + e.getMessage()
                    + ") hashLen=" + hashLen);
        }

        return new BigInteger(byteArray);
    }
}
