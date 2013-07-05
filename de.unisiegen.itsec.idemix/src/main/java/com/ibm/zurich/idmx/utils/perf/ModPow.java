/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

/**
 * Abstraction for the modular exponentiation operation.
 */
public interface ModPow {

    BigInteger modPow(final BigInteger exponent, final BigInteger modulus);

    /**
     * @return max width of exponent in bit.
     */
    int getMaxExpWidth();

    /**
     * @return modulus of exponentiation.
     */
    BigInteger getModulus();

    /**
     * @return exponentiation base.
     */
    BigInteger getBase();

}
