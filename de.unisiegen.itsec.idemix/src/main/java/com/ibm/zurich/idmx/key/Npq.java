/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.key;

import java.math.BigInteger;

/**
 * Private class to hand over the values of n, p and q.
 */
public final class Npq {
    /** Modulus. */
    private BigInteger n;
    /** Safe prime p. */
    private BigInteger p;
    /** Safe prime q. */
    private BigInteger q;

    /**
     * Constructor.
     * 
     * @param theN
     *            Modulus.
     * @param theP
     *            Safe prime p.
     * @param theQ
     *            Safe prime q.
     */
    public Npq(final BigInteger theN, final BigInteger theP,
            final BigInteger theQ) {
        n = theN;
        p = theP;
        q = theQ;
    }

    /**
     * @return Modulus <tt>n</tt>..
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * @return <tt>p</tt>.
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * @return <tt>q</tt>.
     */
    public BigInteger getQ() {
        return q;
    }
}
