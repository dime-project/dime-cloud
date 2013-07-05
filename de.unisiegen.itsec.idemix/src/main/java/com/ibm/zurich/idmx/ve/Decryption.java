/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.ve;

import java.math.BigInteger;

import com.ibm.zurich.idmx.key.VEPrivateKey;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Decryption of a verifiably encrypted ciphertext.
 */
public class Decryption {

    /**
     * @param privateKey
     *            Private key used for decryption.
     * @param encryption
     *            Encryption to be decrypted.
     * 
     * @return Decrypted value of the given encryption.
     */
    public static final BigInteger decrypt(VEPrivateKey privateKey,
            VerifiableEncryption encryption) {
        BigInteger capL = encryption.getCapL();
        BigInteger v = encryption.getV();

        BigInteger n = privateKey.getN();
        BigInteger n2 = privateKey.getN2();

        if (!v.equals(VerifiableEncryption.abs(v, n2))) {
            return null;
        }
        final BigInteger v2 = v.multiply(v).mod(n2);

        BigInteger exp = privateKey.getX2();

        final BigInteger[] arr = new BigInteger[3];
        arr[0] = encryption.getU();
        arr[1] = encryption.getE();
        arr[2] = capL;

        exp = exp.add(Utils.hashOf(
                privateKey.getPublicKey().getSystemParameters().getL_H(), arr)
                .multiply(privateKey.getX3()));
        exp = exp.multiply(Utils.TWO);

        final BigInteger u2 = encryption.getU().modPow(exp, n2);
        if (!u2.equals(v2)) {
            return null;
        }
        // t = (2^(-1) mod n)*2
        final BigInteger t = Utils.TWO.modInverse(n).multiply(Utils.TWO);

        // ux1 = u^(x1) mod n2
        BigInteger ux1 = encryption.getU().modPow(privateKey.getX1(), n2);
        ux1 = ux1.modInverse(n2);

        // mHat = (e/ux1)^(t)
        BigInteger mHat = encryption.getE().multiply(ux1).modPow(t, n2);
        if (!mHat.mod(n).equals(BigInteger.ONE)) {
            return null;
        }
        mHat = mHat.subtract(BigInteger.ONE);
        mHat = mHat.divide(n).mod(n2);
        return mHat;
    }
}
