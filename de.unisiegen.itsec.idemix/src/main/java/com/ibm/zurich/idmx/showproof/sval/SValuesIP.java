/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.showproof.ip.InequalityProver;

/**
 * S-values for inequality proof.
 */
public class SValuesIP {

    /** Logger. */
    private static Logger log = Logger.getLogger(SValuesIP.class.getName());

    /**
     * the uHat values for range proof. for the delta-index we store here the
     * mHat of the attribute.
     */
    private final BigInteger uHat[];
    /** the rHat values for range proof. */
    private final BigInteger rHat[];
    /** alphaHat for range proof. */
    private final BigInteger alphaHat;

    /**
     * Constructor.
     * 
     * @param theUHat
     *            The uHat values for inequality proof. For the delta-index we
     *            store here the mHat of the attribute.
     * @param theRHat
     *            rHat values for inequality proof.
     * @param theAlphaHat
     *            alphaHat for inequality proof.
     */
    public SValuesIP(final BigInteger[] theUHat, final BigInteger[] theRHat,
            final BigInteger theAlphaHat) {
        super();
        uHat = theUHat;
        rHat = theRHat;
        alphaHat = theAlphaHat;
    }

    /**
     * @return The uHat values for range proof. For the delta-index we store the
     *         mHat of the attribute.
     */
    public final BigInteger[] getUHat() {
        return uHat;
    }

    /**
     * @return The rHat values for an inequality proof.
     */
    public final BigInteger[] getRHat() {
        return rHat;
    }

    /**
     * @return The alphaHat for an inequality proof.
     */
    public final BigInteger getAlphaHat() {
        return alphaHat;
    }

    /**
     * @param value
     *            The s-value of the attribute in the CL proof.
     */
    public void addMHat(BigInteger value) {
        BigInteger temp = uHat[InequalityProver.NUM_SQUARES];
        if (temp != null) {
            if (temp.compareTo(value) != 0) {
                log.log(Level.WARNING, "Prover supplied a different value for "
                        + "mHat compared to the CL proof. This might be an "
                        + "indication of a dishonest prover. I will use the "
                        + "value verified in the CL verification.");
            }
        }
        uHat[InequalityProver.NUM_SQUARES] = value;
    }
}
