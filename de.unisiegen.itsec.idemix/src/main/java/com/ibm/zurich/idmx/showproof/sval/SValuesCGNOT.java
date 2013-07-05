/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * Class to store the s-values for the prime encoded NOT proofs.
 */
public class SValuesCGNOT {

    private BigInteger aHat;
    private BigInteger bHat;
    private BigInteger rHatPrime;

    /**
     * Constructor.
     * 
     * @param theAHat
     *            aHat s-value.
     * @param theBHat
     *            bHat s-value.
     * @param theRHatPrime
     *            rHatPrime s-value.
     */
    public SValuesCGNOT(final BigInteger theAHat, final BigInteger theBHat,
            final BigInteger theRHatPrime) {

        aHat = theAHat;
        bHat = theBHat;
        rHatPrime = theRHatPrime;
    }

    /**
     * @return aHat s-value.
     */
    public final BigInteger getAHat() {
        return aHat;
    }

    /**
     * @return bHat s-value.
     */
    public final BigInteger getBHat() {
        return bHat;
    }

    /**
     * @return rHatPrime s-value.
     */
    public final BigInteger getRHatPrime() {
        return rHatPrime;
    }
}
