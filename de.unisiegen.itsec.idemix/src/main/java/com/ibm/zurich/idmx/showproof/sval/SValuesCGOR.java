/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * Class to store the s-values for the prime encoded OR proofs.
 */
public class SValuesCGOR {

    private final BigInteger mHat_i;
    private final BigInteger alphaHat;
    private final BigInteger betaHat;
    private final BigInteger rHat_0;
    private final BigInteger rHat_1;
    private final BigInteger rHat_2;

    // private final BigInteger gammaHat;
    // private final BigInteger deltaHat;
    // private final BigInteger rhoHat_0;
    // private final BigInteger rhoHat_1;
    // private final BigInteger rhoHat_2;

    public SValuesCGOR(final BigInteger theMHat_1,
            final BigInteger theAlphaHat, final BigInteger theBetaHat,
            final BigInteger theRHat_0, final BigInteger theRHat_1,
            final BigInteger theRHat_2) {
        mHat_i = theMHat_1;
        alphaHat = theAlphaHat;
        betaHat = theBetaHat;
        rHat_0 = theRHat_0;
        rHat_1 = theRHat_1;
        rHat_2 = theRHat_2;
    }

    public BigInteger getMHat_i() {
        return mHat_i;
    }

    public BigInteger getAlphaHat() {
        return alphaHat;
    }

    public BigInteger getBetaHat() {
        return betaHat;
    }

    public BigInteger getRHat_0() {
        return rHat_0;
    }

    public BigInteger getRHat_1() {
        return rHat_1;
    }

    public BigInteger getRHat_2() {
        return rHat_2;
    }

    // public BigInteger getGammaHat() {
    // return gammaHat;
    // }
    // public BigInteger getDeltaHat() {
    // return deltaHat;
    // }

}
