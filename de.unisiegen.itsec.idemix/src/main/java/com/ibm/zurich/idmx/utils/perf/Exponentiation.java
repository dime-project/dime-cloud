/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * To describe a modular exponentiation: base, exponent, and modulus.
 */
public class Exponentiation {

    private final ModPow exponentiator;
    private final BigInteger exponent;

    /**
     * Constructor.
     * 
     */
    public Exponentiation(final ModPow theExponentiator,
            final BigInteger theExponent) {
        exponentiator = theExponentiator;
        exponent = theExponent;
    }

    /**
     * Constructor of a description of a modular exponentiation: base^exponent
     * modulo( modulus). In case of cached exponentiators, we look them up and
     * use them. Otherwise the BigInteger built-in exponentiation will be used.
     * 
     * @param base
     *            Base of the exponentiation.
     * @param theExponent
     *            Exponent.
     * @param modulus
     *            Modulus.
     * 
     * @see MultiCoreMultiBase#multiBaseExp(java.util.Vector, BigInteger)
     * @see ModPowCache#lookup(BigInteger)
     */
    public Exponentiation(final BigInteger base, final BigInteger theExponent,
            final BigInteger modulus) {
        exponent = theExponent;
        if (Constants.USE_FAST_EXPO_CACHE) {
            // we may not have cached all bases...
            ModPow exp = ModPowCache.lookup(base);
            if (exp == null) {
                // log.log(Level.INFO, "cache miss");
                exp = new DefModPow(base, modulus);
            }
            exponentiator = exp;
        } else {
            exponentiator = new DefModPow(base, modulus);
        }
    }

    /**
     * @return the exponentiator
     */
    public final ModPow getExponentiator() {
        return exponentiator;
    }

    /**
     * @return the exponent
     */
    public final BigInteger getExponent() {
        return exponent;
    }

    public final String toStringPretty() {
        return "Exponentiation: base = "
                + Utils.logBigInt(exponentiator.getBase()) + ", exp. = "
                + Utils.logBigInt(exponent);
    }

}
