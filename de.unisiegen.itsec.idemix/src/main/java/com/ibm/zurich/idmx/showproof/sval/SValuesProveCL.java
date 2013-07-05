/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * S-values for ProveCL().
 */
public class SValuesProveCL {

    /** eHat value of CL-proof s-values. */
    private final BigInteger eHat;
    /** vHatPrime value of CL-proof s-values. */
    private final BigInteger vHatPrime;

    /**
     * Constructor for CL-proof s-values tied to a given certificate.
     * 
     * @param theEHat
     *            eHat value of CL-proof s-values.
     * @param theVHatPrime
     *            vHatPrime value of CL-proof s-values.
     */
    public SValuesProveCL(final BigInteger theEHat,
            final BigInteger theVHatPrime) {
        eHat = theEHat;
        vHatPrime = theVHatPrime;
    }

    /**
     * @return eHat.
     */
    public final BigInteger getEHat() {
        return eHat;
    }

    /**
     * @return vHat.
     */
    public final BigInteger getVHatPrime() {
        return vHatPrime;
    }

}
