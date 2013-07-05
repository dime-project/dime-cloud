/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Implementation of fixed-base windowing method for exponentiation. Alg 14.109
 * Menezes et al.
 */
public class FixedBaseWindowing implements ModPow {

    private static Logger log = Logger.getLogger(FixedBaseWindowing.class
            .getName());

    /** to hold base^1, base^{expBase}, .. base^{expBase^expBase+1} */
    final BigInteger gb[];

    /** the fixed base we're dealing with. */
    final BigInteger base;

    /**
     * base in which the exponent is represented. We decompose the exponent in a
     * set of digits in this base. Equals 2^digitWidthInBits.
     */
    final int expBase;

    /** width, in bits, of one exponent digit. */
    final int digitWidthInBits;

    /** width, in digits, of exponent. */
    final int expWidthInDigits; // # of digits in expBase in
                                // (exponent)_{expBase}

    /** the modulus we're going to use. */
    final BigInteger modulus;

    /**
     * Constructor.
     * 
     * The constructor pre-computes (base^(2^digitWidthInBits))^digitPos mod(
     * modulus) for 0 <= digitPos <= expWidthInDigits. Thus pre-allocating
     * expWidthInDigits+1 pre-computed values.
     * 
     * @param base
     *            the fixed-base we're going to exponentiate.
     * 
     * @param digitWidthInBits
     *            the nbr. of bits per digit of the exponent. Is used to divide
     *            the exponents into digits of that width.
     * 
     * @param maxExponentWidthInDigits
     *            the maximal nbr of digits in an exponent. Thus, the exponent's
     *            bit-length is digitWidth * maxExponentWidthInDigits.
     * 
     * @param modulus
     *            we compute base^exponent mod( modulus).
     */
    public FixedBaseWindowing(final BigInteger base,
            final int digitWidthInBits, final int maxExponentWidthInDigits,
            final BigInteger modulus) {

        if (digitWidthInBits < 1) {
            throw new IllegalArgumentException();
        }

        this.base = base;
        this.digitWidthInBits = digitWidthInBits;
        this.expBase = (1 << digitWidthInBits);
        this.expWidthInDigits = maxExponentWidthInDigits;
        this.modulus = modulus;

        if (this.base.equals(BigInteger.ZERO)
                || this.base.equals(BigInteger.ONE)) {
            this.gb = null;
            return;
        }

        // System.out.println( "exponent width: " +
        // this.expWidthInDigits*this.digitWidthInBits);
        // System.out.println( "# precomputed group elems: " +
        // (expWidthInDigits+1));

        // allocate space for pre-computed bases raised to some power. Note: the
        // storage
        // required is related to the size of the exponent, i.e. the width of
        // the exponent in digits
        // of with 'digitWidth'.
        log.log(Level.INFO, "allocating " + (expWidthInDigits + 1)
                + " big-ints");
        this.gb = new BigInteger[expWidthInDigits + 1];

        BigInteger exponent = BigInteger.ONE; // exponent grows beyond 32 bits
                                              // quickly...
        final BigInteger _expBase = BigInteger.valueOf(expBase);
        for (int i = 0; i <= expWidthInDigits; i++) {

            // System.out.println( "exponent: " + exponent.toString());

            this.gb[i] = base.modPow(exponent, modulus);
            exponent = exponent.multiply(_expBase);
        }

    }

    /**
     * To compute base^exp mod( modulus) using the pre-computed exponentiated
     * base terms. The base was given to the constructor.
     * 
     * @param exp
     *            exponent. Must not exceed the maximum width of exponent in
     *            digits.
     * 
     * @param modulus
     *            reduction modulus.
     * 
     * @return base^exp mod( modulus)
     * 
     * @see FixedBaseWindowing#FixedBaseWindowing(BigInteger, int, int,
     *      BigInteger)
     */
    public BigInteger modPow(final BigInteger exp, final BigInteger modulus) {
        BigInteger capA = BigInteger.ONE;
        BigInteger capB = BigInteger.ONE;

        if (this.base.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        } else if (this.base.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }

        if (!modulus.equals(this.modulus)) {
            System.err.println("mismatching modulus");
            throw new IllegalArgumentException();
        }

        BigInteger exponent;
        boolean negFlag = false;
        if (exp.compareTo(BigInteger.ZERO) < 0) {
            negFlag = true;
            exponent = exp.negate();
        } else if (exp.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ONE;
        } else {
            exponent = exp;
        }

        final int bitLength = exponent.bitLength();

        if (this.expWidthInDigits * this.digitWidthInBits < bitLength) {

            System.err.println("digit-width: " + this.digitWidthInBits);
            System.err.println("# of digits: " + this.expWidthInDigits);
            System.err.println("exponent bit-length: " + exponent.bitLength());
            System.err.println("exponent width exceeded");

            throw new IllegalArgumentException("exponent width exceeded");
        }

        // compute nbr of right-shifts dependent on digitWidth.
        int nbrOfShifts = bitLength / digitWidthInBits;
        if (bitLength % digitWidthInBits != 0) {
            nbrOfShifts += 1;
        }

        for (int j = this.expBase - 1; j > 0; j--) {

            // iterate over bitgroups of exp

            // we move left to right.
            int digitPos = (nbrOfShifts - 1) * this.digitWidthInBits;

            for (int shifts = nbrOfShifts; shifts > 0; shifts--) {

                int ei = 0; // value of digitWidth bits at pos k.

                // iterate over bits in exp's digit at bit-pos k.
                int bitPos = digitPos;
                for (int bp = 0; bp < this.digitWidthInBits; bp++, bitPos++) {

                    // handle left-margin condition
                    if (bitPos > bitLength) {
                        break;
                    }

                    // test the bit.
                    if (exponent.testBit(bitPos)) {
                        ei |= (1 << bp);
                    }
                }
                // System.out.println( "digitPos[digits]: " +
                // digitPos/this.digitWidthInBits + " ei: " + ei + " j: " + j);

                // we have now computed value of ei at pos digitpos.
                if (ei == j) {
                    int idx = digitPos / this.digitWidthInBits;
                    // System.out.println( "multply in elem[" + idx + "]");
                    capB = capB.multiply(this.gb[idx]).mod(modulus);
                }

                digitPos = digitPos - this.digitWidthInBits;
            }

            capA = capA.multiply(capB).mod(modulus);

        }

        if (negFlag) {
            // we computed base^{-exponent} and need to invert this.
            capA = capA.modInverse(this.modulus);
        }

        return capA; // .mod( modulus);
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
        return this.expWidthInDigits * this.digitWidthInBits;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getModulus()
     */
    public BigInteger getModulus() {
        return this.modulus;
    }
}
