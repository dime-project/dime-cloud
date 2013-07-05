/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * Class to store the s-values for the prime encoded AND proofs.
 */
public class SValuesCGAND {

    private final BigInteger mHat_h;
    private final BigInteger rHat;

    public SValuesCGAND(BigInteger theMHat_h, BigInteger theRHat) {
        mHat_h = theMHat_h;
        rHat = theRHat;
    }

    public BigInteger getMHat_h() {
        return mHat_h;
    }

    public BigInteger getRHat() {
        return rHat;
    }

}
