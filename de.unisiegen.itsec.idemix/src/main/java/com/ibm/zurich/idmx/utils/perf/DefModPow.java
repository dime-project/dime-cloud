/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

/**
 * Default BigInteger exponentiation. A wrapper around BigInteger modPow().
 * 
 * @see BigInteger#modPow(BigInteger, BigInteger)
 */
public class DefModPow implements ModPow {

    private final BigInteger base;
    private final BigInteger modulus;

    public DefModPow(final BigInteger base, final BigInteger modulus) {
        this.base = base;
        this.modulus = modulus;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getBase()
     */
    public BigInteger getBase() {
        return this.base;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getMaxExpWidth()
     */
    public int getMaxExpWidth() {
        return Integer.MAX_VALUE;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getModulus()
     */
    public BigInteger getModulus() {
        return this.modulus;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#modPow(java.math.BigInteger,
     * java.math.BigInteger)
     */
    public BigInteger modPow(BigInteger exponent, BigInteger modulus) {
        if (!modulus.equals(this.modulus)) {
            throw new IllegalArgumentException();
        }
        return this.base.modPow(exponent, modulus);
    }

}
