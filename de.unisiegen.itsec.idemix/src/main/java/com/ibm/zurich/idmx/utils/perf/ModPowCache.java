/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;
import java.util.Hashtable;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.utils.Utils;

/**
 *
 */
public class ModPowCache {

    private static Logger log = Logger.getLogger(ModPowCache.class.getName());

    static private final Hashtable<BigInteger, ModPow> lkupTable = new Hashtable<BigInteger, ModPow>();

    /** for fixed-base comb method; how many rows do we have in exponent array. */
    static private final int ROWS_IN_EXPO_ARR = 5;

    /**
     * for fixed-base comb method; how many columns do we have in lookup table
     * G[][]? This is the v parameter to the algorithm, 0 <= v <= ceil((t+1)/a).
     */
    static private final int NBR_OF_COLS_IN_G = 8;

    /**
     * Creates an instance of a fixed base exponentiator and registers it with
     * look-up table.
     * 
     * @param base
     *            fixed exponentiation base.
     * @param modulus
     *            the modulus under which we perform exponentiations.
     * @param maxExpWidth
     *            max size (in bits) of exponent.
     * @return success or failure.
     */
    public static boolean register(final BigInteger base,
            final BigInteger modulus, final int maxExpWidth) {

        if (base == null || modulus == null || maxExpWidth <= 0) {
            throw new IllegalArgumentException();
        }

        // check for duplicate
        ModPow fbc = lookup(base);
        if (fbc != null) {
            if (!fbc.getModulus().equals(modulus)
                    || !fbc.getBase().equals(base)
                    || fbc.getMaxExpWidth() < maxExpWidth) {
                throw new IllegalArgumentException();
            } else {
                return true;
            }
        }

        log.log(Level.INFO, "registering base: " + Utils.logBigInt(base)
                + ", expWidth: " + maxExpWidth);

        // create accelerator and register it.
        fbc = new FixedBaseComb(base, maxExpWidth, ROWS_IN_EXPO_ARR,
                NBR_OF_COLS_IN_G, modulus);
        lkupTable.put(base, fbc);
        return true;
    }

    /**
     * To look-up the fixed base exponentiator.
     * 
     * @param base
     *            fixed-base we're considering.
     * @return instance of an accelerated modular exponentiator or null if the
     *         base was not registered.
     */
    public static ModPow lookup(final BigInteger base) {
        return lkupTable.get(base);
    }

}
