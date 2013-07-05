/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;
import com.ibm.zurich.idmx.utils.perf.ModPow;
import com.ibm.zurich.idmx.utils.perf.ModPowCache;
import com.ibm.zurich.idmx.utils.perf.MultiCoreMultiBase;
import com.ibm.zurich.idmx.utils.perf.SafePrimes;

/**
 * Set of utilities routines used throughout the library.
 */
public class Utils {

    /** Logger. */
    private static Logger log = Logger.getLogger(Utils.class.getName());

    /** Constant value 2. */
    public static final BigInteger TWO = BigInteger.valueOf(2);

    /** Constant value 4. */
    public static final BigInteger FOUR = BigInteger.valueOf(4);

    /** The single instance of a secure random generator. */
    private static SecureRandom random;

    /** Number of digits that will be shown of a BigInteger. */
    private static final int BIG_INTEGER_VISUALISATION_LENGTH = 12;

    /** Digest used. */
    public static final String DIGEST_METHOD = "SHA-256";

    /** Number of bits per byte. */
    public static final int BYTE_BIT_LENGTH = 8;

    /** Bit length of a SHA-256 hash. */
    private static final int SHA_BIT_LENGTH = 256;

    /**
     * If set to true, the optimised methods for modular exponentiations are
     * used. Otherwise it defaults to the BigInteger methods.
     */
    private static final boolean VALIDATE_FAST_EXPONENTIATION = false;

    static {
        // we generate a unique random number generator and use it throughout
        // the library. In case of developing, we set the seed to a fixed value
        // so that things are deterministic.
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            if (Constants.DEVELOPING) {
                random.setSeed(123);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Constructor.
     */
    protected Utils() {
    }

    /**
     * Returns the secure random number generator.
     * 
     * @return Random number generator.
     */
    public static SecureRandom getRandomGenerator() {
        return random;
    }

    /**
     * Tests if <tt>n</tt> is in given interval <tt>[lower..upper]</tt>.
     * 
     * @param n
     *            Parameter to be tested.
     * @param lower
     *            Lower bound.
     * @param upper
     *            Upper bound.
     * @return True if <tt>lower <= n <= upper</tt>.
     */
    public static boolean isInInterval(final BigInteger n,
            final BigInteger lower, final BigInteger upper) {
        return (lower.compareTo(n) <= 0 && n.compareTo(upper) <= 0);
    }

    /**
     * 
     * Tests if a BigInteger value lies in a given range, indicated by binary
     * exponents, i.e., <tt>arg</tt> in <tt>[ 2^powerLower..2^powerUpper]</tt>.
     * 
     * @param arg
     *            BigInteger to have its bound checked.
     * @param powerLower
     *            Bit length for inclusive lower bound.
     * @param powerUpper
     *            Bit length for inclusive upper bound.
     * 
     * @return True if <tt>arg</tt> is within specified range, i.e.,
     *         <tt>2^powerLower <= arg <= 2^powerUpper</tt>.
     */
    public static boolean isInInterval(final BigInteger arg,
            final int powerLower, final int powerUpper) {

        final BigInteger lowerBound;

        if (powerLower == 0) {
            lowerBound = BigInteger.ONE;
        } else {
            lowerBound = (BigInteger.ONE.shiftLeft(powerLower));
        }
        final BigInteger upperBound = BigInteger.ONE.shiftLeft(powerUpper);

        return isInInterval(arg, lowerBound, upperBound);
    }

    /**
     * Tests if <tt>arg</tt> lies in the interval
     * <tt>[-2^bitlength + 1 .. 2^biglength - 1]</tt>. (math notation
     * <tt>+/-{0,1}^(bitlength}</tt>).
     * 
     * @param arg
     *            Argument to be tested.
     * @param bitLength
     *            Bit length of the interval.
     * @return True if <tt>-2^bitlength + 1 <= arg <= 2^biglength - 1</tt>.
     */
    public static boolean isInInterval(final BigInteger arg, final int bitLength) {
        BigInteger upperBound = BigInteger.ONE.shiftLeft(bitLength);
        BigInteger lowerBound = upperBound.negate();
        upperBound = upperBound.subtract(BigInteger.ONE);
        lowerBound = lowerBound.add(BigInteger.ONE);
        return isInInterval(arg, lowerBound, upperBound);
    }

    /**
     * Returns a statistically uniformly distributed random number from the
     * interval <tt>[lower..upper]</tt>.
     * 
     * @param lower
     *            Lower bound.
     * @param upper
     *            Upper bound.
     * @param sp
     *            System parameters.
     * @return Random number in the given range.
     */
    public static BigInteger computeRandomNumber(final BigInteger lower,
            final BigInteger upper, final SystemParameters sp) {
        final BigInteger delta = upper.subtract(lower).add(BigInteger.ONE);
        BigInteger temp = computeRandomNumber(delta, sp);
        return temp.add(lower);
    }

    /**
     * Returns a statistically uniformly distributed random number from the
     * interval <tt>[0..upper-1]</tt>.
     * 
     * @param upper
     *            Upper bound.
     * @param sp
     *            System parameters.
     * @return Random number in the given range.
     */
    public static BigInteger computeRandomNumber(final BigInteger upper,
            final SystemParameters sp) {
        return new BigInteger((upper.bitLength() + sp.getL_Phi()), random)
                .mod(upper);
    }

    /**
     * Returns a random number in the range of <tt>[0..(2^bitlength)-1]</tt>.
     * (math notation: <tt>\{0,1\}^{bitlength}</tt> (MSB always 0 to stay >=
     * 0)).
     * 
     * @param bitlength
     *            Bit length.
     * @return Positive random number <tt>[0..(2^bitlength)-1]</tt>.
     * 
     * @see java.math.BigInteger#BigInteger(int, java.util.Random)
     */
    public static BigInteger computeRandomNumber(final int bitlength,
            boolean symmetry) {
        if (symmetry) {
            return computeRandomNumberSymmetric(bitlength);
        } else {
            return new BigInteger(bitlength, random);
        }
    }

    /**
     * Returns a random number in the range of <tt>[0..(2^bitlength)-1]</tt>.
     * (math notation: <tt>\{0,1\}^{bitlength}</tt> (MSB always 0 to stay >=
     * 0)).
     * 
     * @param bitlength
     *            Bit length.
     * @return Positive random number <tt>[0..(2^bitlength)-1]</tt>.
     * 
     * @see java.math.BigInteger#BigInteger(int, java.util.Random)
     */
    public static BigInteger computeRandomNumber(final int bitlength) {
        return new BigInteger(bitlength, random);
    }

    /**
     * Returns a random number in the interval
     * <tt>[-2<sup>bitlength</sup>+1..2<sup>bitlength</sup>-1]</tt>.<br/>
     * (math notation: <tt>+/-{0,1}<sup>bitlength</sup></tt>).
     * 
     * @param bitlength
     *            Bit length of the random number.
     * @return Random number
     *         <tt>[-2<sup>bitlength</sup>+1..2<sup>bitlength</sup>-1]</tt>.
     * 
     * @see java.math.BigInteger#BigInteger(int, java.util.Random)
     */
    public static BigInteger computeRandomNumberSymmetric(final int bitlength) {
        BigInteger temp = new BigInteger(bitlength, random);
        // 0 <= temp <= 2^bitlength - 1
        // TODO (frp): probability is not uniform any more: zero has a slightly
        // bigger chance of being selected
        final boolean flipSignBit = random.nextBoolean();
        if (flipSignBit) {
            // randomly negate temp
            temp = temp.negate();
        }

        // -2^bitlength+1 <= temp <= 2^bitlength-1
        return temp;
    }

    /**
     * Tests if <tt>n</tt> is odd.
     * 
     * @param n
     *            Parameter to be tested.
     * @return True if <tt>n</tt> is odd.
     */
    public static boolean isOdd(final BigInteger n) {
        return n.mod(TWO) != BigInteger.ZERO;
    }

    /**
     * Generates a random number of bitLength bit length. The first two bits and
     * the last bit of this number are always set, therefore the number is odd
     * and <tt>>= (2^(bitLength-1)+2^(bitLength-2)+1)</tt>.
     * 
     * @param bitLength
     *            Length of the number to be generated, in bits.
     * @param theRandom
     *            Secure random number generator.
     * @return A random number of bitLength bit length with first and last bits
     *         set.
     */
    public static BigInteger randomOddBigNumber(final int bitLength,
            final SecureRandom theRandom) {
        if (bitLength <= 0) {
            throw new IllegalArgumentException("bitLenght must be > 0");
        }
        final BigInteger temp = new BigInteger(bitLength, theRandom);
        final BigInteger ret = temp.setBit(0).setBit(bitLength - 1);
        if (!isOdd(ret)) {
            log.log(Level.SEVERE, "Can not generate Odd Number");
            throw new RuntimeException();
        }
        return ret;
    }

    /**
     * Generates a number that is a regular prime number with a given
     * probability and that is of the given bit length.
     * 
     * @param bitLength
     *            Bit length of the generated number.
     * @param primeCertainty
     *            Certainty of the number being a prime.
     * @return Probable prime (with indicated certainty) of the given length.
     */
    public static BigInteger genPrime(final int bitLength,
            final int primeCertainty) {

        BigInteger p = null;
        do {
            p = randomOddBigNumber(bitLength - 1, random);
        } while (!p.isProbablePrime(primeCertainty));
        return p;
    }

    // /**
    // * Pre-computed a list of small primes.
    // */
    // protected static List<BigInteger> listOfSmallPrimes =
    // generateSmallPrimes(16384, 3);
    //
    // /**
    // * Generates small prime numbers up to a specified bound using the Sieve
    // of
    // * Eratosthenes algorithm.
    // *
    // * @param primeBound
    // * The upper bound for the primes to be generated.
    // * @param startingPrime
    // * The first prime in the list of primes that is returned.
    // * @return List of primes up to the specified bound as BigInteger objects.
    // */
    // private static ArrayList<BigInteger> generateSmallPrimes(
    // final int primeBound, int startingPrime) {
    // ArrayList<BigInteger> res = new ArrayList<BigInteger>();
    // if ((primeBound <= 1) || (startingPrime > primeBound))
    // return res;
    // if (startingPrime <= 2) {
    // startingPrime = 2;
    // res.add(TWO);
    // }
    // boolean[] primes = new boolean[(int) ((primeBound - 1) / 2)];
    // int i, k, prime;
    // for (i = 0; i < primes.length; i++)
    // primes[i] = true;
    // for (i = 0; i < primes.length; i++) {
    // if (primes[i]) {
    // prime = 2 * i + 3;
    // for (k = i + prime; k < primes.length; k += prime)
    // primes[k] = false;
    // if (prime >= startingPrime)
    // res.add(BigInteger.valueOf(prime));
    // }
    // }
    // return res;
    // }
    //
    // /**
    // * Test whether the provided <tt>p'</tt> or <tt>p = 2*p' + 1</tt> are
    // divisible by any of
    // * the small primes saved in the <tt>listOfSmallPrimes</tt>. A limit for
    // the
    // * largest prime to be tested against can be specified, but it will be
    // * ignored if it exceeds the number of pre-calculated primes.
    // *
    // * @param primeP
    // * The number to be tested.
    // * @param primeBound
    // * The limit for the small primes to be tested against.
    // */
    // private static boolean testSmallPrimeFactors(final BigInteger primeP,
    // final BigInteger primeBound) {
    // ListIterator primes = listOfSmallPrimes.listIterator();
    // boolean sievePassed = true;
    // BigInteger smallPrime = BigInteger.ONE;
    //
    // while (primes.hasNext() && (smallPrime.compareTo(primeBound) < 0)) {
    // smallPrime = (BigInteger) primes.next();
    // BigInteger r = primeP.remainder(smallPrime);
    // // test if primeP = 0 (mod smallPrime)
    // if (r.compareTo(BigInteger.ZERO) == 0) {
    // sievePassed = false;
    // break;
    // }
    // // test if p == 0 (mod smallPrime) (or r == smallPrime - r - 1)
    // if (r.compareTo(smallPrime.subtract(r).subtract(BigInteger.ONE)) == 0) {
    // sievePassed = false;
    // break;
    // } else {
    // }
    // }
    // return sievePassed;
    // }
    //
    // /**
    // * Implements the MillerRabin primality test.
    // *
    // * @param n
    // * the number to be tested.
    // * @param s
    // * number of iterations of the MillerRabin test.
    // * @param random
    // * a random number generator.
    // * @return true if <tt>n</tt> is considered to be prime.
    // */
    // private static boolean isMillerRabinPrime(final BigInteger n, final int
    // s,
    // final SecureRandom random) {
    // BigInteger a;
    // for (int i = 0; i < s; i++) {
    // do {
    // a = new BigInteger(n.bitLength() - 1, random);
    // } while (a.compareTo(BigInteger.ZERO) <= 0 || a.compareTo(n) >= 0);
    // if (isMillerRabinWitness(a, n)) {
    // return false;
    // }
    // }
    // return true;
    // }
    //
    // /**
    // * Tests if <tt>a</tt> is a Miller-Rabin witness for <tt>n</tt>.
    // *
    // * @param a
    // * number which is supposed to be the witness.
    // * @param n
    // * number to be tested against.
    // * @return true if <tt>a</tt> is Miller-Rabin witness for <tt>n</tt>.
    // */
    // private static boolean isMillerRabinWitness(final BigInteger A,
    // final BigInteger N) {
    // BigInteger N_1 = N.subtract(BigInteger.ONE);
    // int t = 0;
    //
    // while (N_1.divide(TWO.pow(t)).mod(TWO).compareTo(BigInteger.ZERO) == 0)
    // t++;
    // final BigInteger U = N_1.divide(TWO.pow(t));
    //
    // BigInteger x0;
    // BigInteger x1 = A.modPow(U, N);
    //
    // for (int i = 0; i < t; i++) {
    // x0 = x1;
    // x1 = x0.modPow(TWO, N);
    // if (x1.compareTo(BigInteger.ONE) == 0
    // && x0.compareTo(BigInteger.ONE) != 0
    // && x0.compareTo(N_1) != 0)
    // return true;
    // }
    // if (x1.compareTo(BigInteger.ONE) != 0)
    // return true;
    // else
    // return false;
    // }

    // private static boolean IS_STANDARD_BIGINTEGER_TEST_ENABLED = true;

    /**
     * The main method to compute a random safe prime of the specified bit
     * length. IMPORTANT: The computed prime will have two first bits and the
     * last bit set to 1! That is, the prime is greater than
     * <tt>(2^(bitlength-1)+2^(bitlength-2)+1)</tt>. This is done to be sure
     * that if two primes of bit length <tt>n</tt> are multiplied, the result
     * will have the bitLength of <tt>2*n</tt> exactly.
     * 
     * TODO (bus) check if we can still keep the following comment for Open
     * Source: This implementation uses the algorithm proposed by Ronald Cramer
     * and Victor Shoup in "Signature Schemes Based on the strong RSA
     * Assumption" May 9, 2000.
     * 
     * @param bitlength
     *            the bit length of the safe prime to be computed.
     * @param primeCertainty
     *            the probability that the computed number is not prime is
     *            <tt>(2^(-primeCertainty))</tt>.
     * @return a number which is considered to be a safe prime with the prime
     *         certainty as specified.
     */
    public static BigInteger computeSafePrime(final int bitlength,
            final int primeCertainty) {

        final SafePrimes safePrime = SafePrimes.getInstance();
        if (Constants.USE_MULTI_CORE_SAFE_PRIMES) {
            safePrime.setForceSingleThread(false);
            return safePrime.genSafePrime(bitlength, primeCertainty);
        } else {
            safePrime.setForceSingleThread(true);
            return safePrime.genSafePrime(bitlength, primeCertainty);
        }

        // BigInteger p, pDash, tempP, primeBound;
        // int mrTests;
        //
        // // some heuristic checks to limit the number of small primes to check
        // // against and the number of Miller-Rabin primality tests at the end
        // if (bitlength <= 256) {
        // primeBound = BigInteger.valueOf(768);
        // mrTests = 27;
        // } else if (bitlength <= 512) {
        // primeBound = BigInteger.valueOf(3072);
        // mrTests = 15;
        // } else if (bitlength <= 768) {
        // primeBound = BigInteger.valueOf(6144);
        // mrTests = 8;
        // } else if (bitlength <= 1024) {
        // primeBound = BigInteger.valueOf(10240);
        // mrTests = 4;
        // } else {
        // primeBound = BigInteger.valueOf(16384);
        // mrTests = 4;
        // }
        //
        // boolean stop = false;
        // do {
        // // generate random, odd pDash
        // pDash = randomOddBigNumber(bitlength - 1);
        //
        // // calculate p = 2*pDash+1 p =
        // pDash.shiftLeft(1).add(BigInteger.ONE);
        //
        // // test if pDash or p are divisible by some small primes
        // if (!testSmallPrimeFactors(pDash, primeBound)) {
        // continue;
        // }
        // // test if 2 is a compositness witness for pDash or p
        // if (isMillerRabinWitness(TWO, pDash)) {
        // continue;
        // }
        //
        // // test if 2^(pDash) == +1/-1 (mod p) tempP = TWO.modPow(pDash, p);
        // if ((tempP.compareTo(BigInteger.ONE) != 0)
        // && (tempP.compareTo(p.subtract(BigInteger.ONE)) != 0)) {
        // continue;
        // }
        //
        // if (!IS_STANDARD_BIGINTEGER_TEST_ENABLED) {
        // if (isMillerRabinPrime(pDash, mrTests, random)) {
        // stop = true;
        // }
        // } else {
        // // use the BigInteger primality check, implements MillerRabin
        // // and LucasLehmer
        // if (pDash.isProbablePrime(primeCertainty)) {
        // stop = true;
        // }
        // }
        // } while (!stop);
        //
        // return p;
    }

    // /**
    // * Computes a generator for a group specified by a modulus and the group
    // * order.
    // *
    // * @param modulus
    // * the modulus.
    // * @param groupOrder
    // * the group order.
    // * @param sp
    // * System parameters.
    // * @return generator of a group with order <tt>groupOrder</tt> and modulus
    // * <tt>modulus</tt>.
    // */
    // public static BigInteger computeGenerator(final BigInteger modulus,
    // final BigInteger groupOrder, final SystemParameters sp) {
    // BigInteger r;
    // BigInteger g;
    // do {
    // r = Utils.computeRandomNumber(modulus, sp);
    // g = r.modPow(groupOrder, modulus);
    // // we have ord( r) == ord( group) in case of generator.
    // } while (!g.equals(BigInteger.ONE));
    // return r;
    // }

    /**
     * Compute a generator of the group of quadratic residue modulo <tt>n</tt>.
     * The generator will not be part of the subgroup of size 2.
     * 
     * @param n
     *            the modulus.
     * @param sp
     *            System parameters.
     * @return group generator of group of quadratic residues modulo <tt>n</tt>.
     */
    public static BigInteger computeGeneratorQuadraticResidue(
            final BigInteger n, final SystemParameters sp) {
        BigInteger qr;
        do {
            qr = Utils.computeRandomNumber(n, sp);
            qr = qr.modPow(TWO, n);
            // verify that the qr is a generator but not of the subgroup of size
            // 2
        } while (qr.equals(BigInteger.ONE)
                || !n.gcd(qr.subtract(BigInteger.ONE)).equals(BigInteger.ONE));
        return qr;
    }

    /**
     * Computes a hash value (SHA-256) of the given string.
     * 
     * @param str
     *            String to be hashed.
     * @param l_H
     *            Bit length of the hash.
     * @return Hash value of string.
     */
    public static BigInteger hashString(final String str, final int l_H) {

        // length in bytes
        int hashLen = l_H / BYTE_BIT_LENGTH;
        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            throw new RuntimeException(e1.getMessage());
        }

        final byte[] preImage = str.getBytes();
        digest.update(preImage, 0, preImage.length);

        final byte[] byteArray = new byte[hashLen];
        try {
            digest.digest(byteArray, 0, hashLen);
        } catch (Exception e) {
            throw new RuntimeException("Digest error (" + e.getMessage()
                    + ") hashLen=" + hashLen);
        }
        return new BigInteger(byteArray);
    }

    /**
     * Hashes an array of BigIntegers into a single BigInteger value. This is
     * used during the Fiat-Shamir hash computations. The system parameter
     * <tt>l_H</tt> is used as hash length.
     * 
     * @param array
     *            array of BigInteger.
     * @param l_H
     *            System parameter: Bit length of a hash.
     * @return hashed value of <tt>array</tt>.
     * 
     * @see SystemParameters#getL_H()
     */
    public static BigInteger hashOf(final int l_H, final BigInteger[] array) {

        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            log.log(Level.SEVERE, e1.getMessage(), e1);
            throw new RuntimeException(e1.getMessage());
        }

        // length in bytes
        int hashLen = l_H / BYTE_BIT_LENGTH;
        if (DIGEST_METHOD.equals("SHA-256")) {
            if (hashLen < SHA_BIT_LENGTH / BYTE_BIT_LENGTH) {
                log.log(Level.SEVERE, "SHA-256: hashLen < " + SHA_BIT_LENGTH
                        + "/" + BYTE_BIT_LENGTH + " (" + hashLen + ")");
                throw new RuntimeException("Digest error");
            }
        }

        final byte[] asn1representation = idemix_asn.encode(array);

        digest.update(asn1representation, 0, asn1representation.length);

        final byte[] byteArray = new byte[hashLen];
        try {
            digest.digest(byteArray, 0, hashLen);
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error calculating ASN1 hash", e);
            throw new RuntimeException("Digest error");
        }
        return new BigInteger(1, byteArray);
    }

    public static BigInteger hashOf(final int l_H, final Vector<BigInteger> list) {

        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            log.log(Level.SEVERE, e1.getMessage(), e1);
            throw new RuntimeException(e1.getMessage());
        }

        // length in bytes
        int hashLen = l_H / BYTE_BIT_LENGTH;
        if (DIGEST_METHOD.equals("SHA-256")) {
            if (hashLen < SHA_BIT_LENGTH / BYTE_BIT_LENGTH) {
                log.log(Level.SEVERE, "SHA-256: hashLen < " + SHA_BIT_LENGTH
                        + "/" + BYTE_BIT_LENGTH + " (" + hashLen + ")");
                throw new RuntimeException("Digest error");
            }
        }

        BigInteger[] array = new BigInteger[list.size()];
        list.toArray(array);

        final byte[] asn1representation = idemix_asn.encode(array);
        digest.update(asn1representation, 0, asn1representation.length);

        final byte[] byteArray = new byte[hashLen];
        try {
            digest.digest(byteArray, 0, hashLen);
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error calculating ASN1 hash", e);
            throw new RuntimeException("Digest error");
        }
        return new BigInteger(1, byteArray);
    }

    /**
     * Calculates the product of a given vector of constants.
     * 
     * @param constants
     *            Constants that will be multiplied.
     * @return Product of all constants contained in the given vector.
     */
    public static BigInteger product(final Vector<BigInteger> constants) {
        Iterator<BigInteger> iterator = constants.iterator();
        BigInteger product = BigInteger.ONE;

        while (iterator.hasNext()) {
            product = product.multiply(iterator.next());
        }
        return product;
    }

    /**
     * Convenience for logging of BigInteger.
     * 
     * @param number
     *            BigInteger to be represented.
     * @return The first and last {@link Utils#BIG_INTEGER_VISUALISATION_LENGTH}
     *         digits of <tt>number</tt>.
     */
    public static String logBigInt(final BigInteger number) {
        if (number == null) {
            return "null";
        }
        final String istr = number.toString();
        int len = istr.length();
        if (len > BIG_INTEGER_VISUALISATION_LENGTH) {
            // we concatenate the beginning and the end of the string
            // and cut out the middle.
            final String tail = istr.substring(len
                    - BIG_INTEGER_VISUALISATION_LENGTH / 2, len);
            final String tail2 = " (" + number.bitLength() + ")";
            return istr.substring(0, BIG_INTEGER_VISUALISATION_LENGTH / 2)
                    .concat("...").concat(tail).concat(tail2);
        } else {
            return istr;
        }
    }

    /**
     * String representation of an array of BigInteger, using the
     * {@link Utils#logBigInt(BigInteger)} method.
     * 
     * @param numbers
     *            Array of BigIntegers to be presented.
     * @return String containing all of the BigIntegers in <tt>array</tt>, in
     *         the correct order.
     * 
     * @see Utils#logBigInt(BigInteger)
     */
    public static String logArray(final BigInteger[] numbers) {
        String delimiter = "\n\t\t\t\t\t";
        String s = delimiter;
        for (int i = 0; i < numbers.length - 1; i++) {
            s += i + ": " + Utils.logBigInt(numbers[i]) + delimiter;
        }
        s += Utils.logBigInt(numbers[numbers.length - 1]);
        return s;

    }

    /**
     * String representation of a vector of BigInteger, using the logBitInt()
     * method.
     * 
     * @param numbers
     *            Vector of BigIntegers to be presented.
     * @return String containing all of the BigIntegers in <tt>numbers</tt>, in
     *         the correct order.
     * 
     * @see Utils#logArray(BigInteger[])
     */
    public static String logVector(final Vector<BigInteger> numbers) {
        BigInteger[] numberArray = (BigInteger[]) numbers.toArray();
        return logArray(numberArray);
    }

    /**
     * Calculates the modular exponentiation with
     * <tt>base^exponent (mod modulus)</tt> and returns the result.
     * 
     * @param base
     *            Base of the exponentiation.
     * @param exponent
     *            Exponent.
     * @param modulus
     *            Modulus.
     * @return <tt>base^exponent (mod modulus)</tt>.
     */
    public static BigInteger modPow(final BigInteger base,
            final BigInteger exponent, final BigInteger modulus) {
        BigInteger t;
        // TODO (frp): check this branch
        if (Constants.USE_FAST_EXPO_CACHE) {
            final ModPow mp = ModPowCache.lookup(base);
            if (mp == null) { // no cached info. go the java.math.BigInteger
                // route
                t = base.modPow(exponent, modulus);
            } else { // use the cached exponentiation accelerator.
                t = mp.modPow(exponent, modulus);
                if (VALIDATE_FAST_EXPONENTIATION) {
                    BigInteger tt = base.modPow(exponent, modulus);
                    if (!tt.equals(t)) {
                        log.log(Level.SEVERE, "mismatch in exponentiation");
                        log.log(Level.SEVERE, "base: " + base.toString());
                        log.log(Level.SEVERE,
                                "exponent: " + exponent.toString());
                        log.log(Level.SEVERE, "modulus: " + modulus.toString());
                        log.log(Level.SEVERE, "trusted res: " + tt.toString());
                        log.log(Level.SEVERE, "sped-up res: " + t.toString());
                        throw new RuntimeException();
                    }
                }
            }
        } else {
            // go the straightforward way, using java.math.BigInteger
            t = base.modPow(exponent, modulus);
        }
        return t;
    }

    /**
     * Expose and multiply modulo modulus operation. This is the heart of the
     * Idemix algorithms and thus we have this convenience method. It also is
     * the place to start optimizations.
     * 
     * @param product
     *            Product that will be multiplied with the product of the
     *            exponentiation. MAY be <tt>null</tt>.
     * @param base
     *            Base of the exponentiation.
     * @param exponent
     *            Exponent.
     * @param modulus
     *            Modulus.
     * @return <tt>product * base^exponent (mod modulus)</tt>.
     */
    public static BigInteger expMul(final BigInteger product,
            final BigInteger base, final BigInteger exponent,
            final BigInteger modulus) {

        // t = base^exponent (mod modulus)
        BigInteger t = null;

        // we've learned to handle the special cases, though in the Idemix
        // environment, these probably never ever happen and presumably the
        // BigInteger package would handle these special cases under the hood.
        if (base.equals(BigInteger.ZERO)) {
            t = BigInteger.ZERO;
        } else if (base.equals(BigInteger.ONE)) {
            t = BigInteger.ONE;
        } else if (exponent.equals(BigInteger.ZERO)) {
            t = BigInteger.ONE;
        } else if (exponent.equals(BigInteger.ONE)) {
            t = base.mod(modulus);
        } else {
            // some real work to do.
            t = Utils.modPow(base, exponent, modulus);
        }

        if (product == null || product.equals(BigInteger.ONE)) {
            return t;
        } else if (product.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }

        return product.multiply(t).mod(modulus);
    }

    /**
     * Computes the product of a set of modular exponentiations.
     * 
     * @param exponentiations
     *            Vector containing the exponentiations.
     * @param modulus
     *            Modulus.
     * @return Product of exponentiations, modulo <tt>modulus</tt>.
     */
    public static BigInteger multiExpMul(
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {
        if (Constants.USE_MULTI_CORE_EXP) { // use multi-core exponentiation.
            final MultiCoreMultiBase mcmb = MultiCoreMultiBase.getInstance();
            if (mcmb == null) {
                log.log(Level.SEVERE,
                        "can't get instance of MultiCoreMultiBase");
                throw new RuntimeException();
            }
            return mcmb.multiBaseExp(exponentiations, modulus);
        } else { // use single-threaded default.
            return MultiCoreMultiBase.compute(exponentiations, modulus);
        }
    }

    // public static BigInteger multiExpMul(final Vector<Expo> exponentiations)
    // {
    // if (Constants.USE_MULTI_CORE_EXP) {
    // // use multi-core exponentiation.
    // throw new RuntimeException("Multi-threaded version not yet "
    // + "implemented.");
    // } else {
    // // use single-threaded version.
    // return MultiCoreMultiBase.compute(null, exponentiations);
    // }
    // }

    /**
     * Computes the product of a set of of modular exponentiations, with a given
     * initial value of the product.
     * 
     * @param initialVal
     *            initial value of product.
     * @param exponentiations
     *            the vector containing the exponentiations.
     * @param modulus
     *            the modulus.
     * @return Product of exponentiations times initial-value, modulo( modulus).
     */
    public static BigInteger multiExpMul(final BigInteger initialVal,
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {

        // nothing to do
        if (exponentiations.size() == 0) {
            return initialVal;
        }

        if (Constants.USE_MULTI_CORE_EXP) { // use multi-core exponentiation.
            final MultiCoreMultiBase mcmb = MultiCoreMultiBase.getInstance();
            if (mcmb == null) {
                log.log(Level.SEVERE,
                        "can't get instance of MultiCoreMultiBase");
                throw new RuntimeException();
            }
            return mcmb.multiBaseExp(initialVal, exponentiations, modulus);
        } else { // use single-threaded default.
            return MultiCoreMultiBase.compute(initialVal, exponentiations,
                    modulus);
        }
    }

    /**
     * Outputs the bases of the exponentiations contained in <tt>vec</tt>.
     * 
     * @param vec
     *            vector containing exponentiations.
     * @return string with all the bases of the given exponentiations.
     */
    public static String basesToString(final Vector<Exponentiation> vec) {
        String s = "";
        for (int i = 0; i < vec.size() - 1; i++) {
            Exponentiation e = vec.elementAt(i);
            s += Utils.logBigInt(e.getExponentiator().getBase()) + ", ";
        }
        s += Utils.logBigInt(vec.elementAt(vec.size() - 1).getExponentiator()
                .getBase());
        return s;
    }

    /**
     * Computes <tt>s</tt> and <tt>t</tt> such that
     * <tt>a*s + b*t = gcd(a, b)</tt>. Using the extended Euclid algorithm as
     * described in "A Computational Introduction to Number Theory and Algebra"
     * by Victor Shoup the values of <tt>s</tt> and <tt>t</tt> are computed and
     * returned as an array.
     * 
     * @param a
     *            first argument of the gcd method.
     * @param b
     *            second argument of the gcd method.
     * @return array [s,t] such that <tt>s*a + t*b = gcd(a,b)</tt>.
     */
    public static BigInteger[] extendedEuclid(final BigInteger a,
            final BigInteger b) {

        BigInteger[] result = new BigInteger[2];
        BigInteger r, r0, r00, q;
        BigInteger s = BigInteger.ONE;
        BigInteger s0 = BigInteger.ZERO;
        BigInteger t = BigInteger.ZERO;
        BigInteger t0 = BigInteger.ONE;

        if (a.compareTo(b) < 0) {
            r = b;
            r0 = a;
        } else {
            r = a;
            r0 = b;
        }

        while (r0.compareTo(BigInteger.ZERO) != 0) {
            q = r.divide(r0);
            r00 = r.mod(r0);
            r = r0;
            final BigInteger ss = s0;
            final BigInteger tt = t0;
            r0 = r00;
            t0 = t.subtract(t0.multiply(q));
            s0 = s.subtract(s0.multiply(q));
            s = ss;
            t = tt;
        }
        if (a.compareTo(b) < 0) {
            result[0] = t;
            result[1] = s;
        } else {
            result[0] = s;
            result[1] = t;
        }

        return result;
    }

    /**
     * This method computes the Fiat-Shamir challenges for both the Recipient
     * and the Issuer. Note that the values must be set properly: distinction
     * between tilde-values and hat-Values for Recipient vs. Issuer. But since
     * the FS challenge is rather symmetrical, it made sense to have one method
     * to assemble the data and compute the hash.
     * 
     * @param sp
     *            System parameters (used to retrieve the bit length of the
     *            hash).
     * @param context
     *            Context (hashed for security reasons).
     * @param capU
     *            Common value of the CL proof.
     * @param attStructs
     *            Attribute structures (used for the committed attributes).
     * @param theValues
     *            Values (used to retrieve the commitments).
     * @param nym
     *            Pseudonym (may be null).
     * @param domNym
     *            Domain pseudonym (may be null).
     * @param capUTilde
     *            T-value of the proof.
     * @param capCTilde
     *            Additional commitments (needed for the committed attributes).
     * @param nymTilde
     *            Additional commitment.
     * @param domNymTilde
     *            Additional commitment.
     * @param n1
     *            Nonce.
     * 
     * @return Fiat-Shamir hash value.
     */
    public static final BigInteger computeFSChallenge(
            final SystemParameters sp, final BigInteger context,
            final BigInteger capU, final Vector<AttributeStructure> attStructs,
            final Values theValues, final BigInteger nym,
            final BigInteger domNym, final BigInteger capUTilde,
            final HashMap<String, BigInteger> capCTilde,
            final BigInteger nymTilde, final BigInteger domNymTilde,
            final BigInteger n1) {

        if ((nym == null && nymTilde != null)
                || (nym != null && nymTilde == null)) {
            throw new IllegalArgumentException();
        }
        if ((domNym == null && domNymTilde != null)
                || (domNym != null && domNymTilde == null)) {
            throw new IllegalArgumentException();
        }

        // calculate the length of the array we need for c
        // context, capU
        int len = 2;
        // commitments c1..ck
        len += capCTilde.size();
        // Nym and NymTilde
        if (nym != null) {
            len += 2;
        }
        // DomNym and DomNymTilde
        if (domNym != null) {
            len += 2;
        }
        // UTilde
        len++;
        // CTilde
        len += capCTilde.size();
        // nonce n1
        len++;

        log.log(Level.FINE, "Length: " + len);
        log.log(Level.FINE, "context: " + Utils.logBigInt(context));
        log.log(Level.FINE, "capU: " + Utils.logBigInt(capU));
        log.log(Level.FINE, "U1: " + Utils.logBigInt(capUTilde));

        // allocate the array of BigInteger
        final BigInteger[] arr = new BigInteger[len];

        int i = 0;
        arr[i++] = context;
        arr[i++] = capU;
        int j = 0;
        for (AttributeStructure attStruct : attStructs) {
            // the committed value!
            if (attStruct.getIssuanceMode() != IssuanceMode.COMMITTED) {
                continue;
            }
            final BigInteger committedValue = ((Commitment) theValues.get(
                    attStruct.getName()).getContent()).getCommitment();
            log.log(Level.FINE,
                    "c[" + (j++) + "]:" + Utils.logBigInt(committedValue));
            arr[i++] = committedValue;
        }
        if (nym != null) {
            arr[i++] = nym;
            log.log(Level.FINE, Utils.logBigInt(nym));
        }
        if (domNym != null) {
            arr[i++] = domNym;
            log.log(Level.FINE, Utils.logBigInt(domNym));
        }
        j = 0;
        arr[i++] = capUTilde;
        for (AttributeStructure attStruct : attStructs) {
            if (attStruct.getIssuanceMode() != IssuanceMode.COMMITTED) {
                continue;
            }
            final BigInteger cTildeValue = capCTilde.get(attStruct.getName());
            log.log(Level.FINE,
                    "cTilde[" + (j++) + "]:" + Utils.logBigInt(cTildeValue));
            arr[i++] = cTildeValue;
        }
        if (nym != null) {
            arr[i++] = nymTilde;
            log.log(Level.FINE, Utils.logBigInt(nymTilde));
        }
        if (domNym != null) {
            arr[i++] = domNymTilde;
            log.log(Level.FINE, Utils.logBigInt(domNymTilde));
        }
        arr[i++] = n1;

        // hash the array of BigIntegers
        return Utils.hashOf(sp.getL_H(), arr);
    }

    /**
     * Computes the Fiat-Shamir challenge. Note: this method is also used in the
     * verification.
     * 
     * @param sp
     *            System parameters.
     * @param context
     *            Context for the proof.
     * @param bigIntList
     *            List of values that will be included into the hash.
     * @param n1
     *            Nonce to make the proof.
     * @param messages
     *            Messages.
     * @return Value of Fiat-Shamir challenge.
     */
    public static BigInteger computeChallenge(final SystemParameters sp,
            final BigInteger context, final Vector<BigInteger> bigIntList,
            final BigInteger n1, final Collection<MessageToSign> messages) {
        // TODO (pbi) merge with the computeFSChallenge()

        // context + n1
        int len = 2;
        len += bigIntList.size();
        if (messages != null) {
            // one value for type, one value for message itself.
            len += messages.size();
        }

        BigInteger[] arr = new BigInteger[len];
        int i = 0;

        log.log(Level.FINE, "computing challenge[Hat]: len = " + len);
        log.log(Level.FINE, " context = " + Utils.logBigInt(context));

        arr[i++] = context;

        int iStart = i;
        for (BigInteger bigInt : bigIntList) {
            log.log(Level.FINE,
                    " T[" + (i - iStart) + "] = " + Utils.logBigInt(bigInt));
            arr[i++] = bigInt;
        }
        arr[i++] = n1;

        iStart = i;
        if (messages != null) {
            for (MessageToSign msg : messages) {
                log.log(Level.FINE,
                        "message [" + (i - iStart) + ": " + msg.getBytes());
                arr[i++] = msg.getHash(sp);
            }
        }
        log.log(Level.FINE, "array to be hashed:" + Utils.logArray(arr));
        log.log(Level.FINE,
                "Challenge:" + Utils.logBigInt(Utils.hashOf(sp.getL_H(), arr)));
        return Utils.hashOf(sp.getL_H(), arr);
    }

    /**
     * Compute the context. This is a hash over all the public parameters and
     * the issuer public key.
     * 
     * @return Context for the proof.
     */
    public static final BigInteger computeContext(IssuerPublicKey pk) {
        final GroupParameters gp = pk.getGroupParams();

        Vector<BigInteger> contextVector = new Vector<BigInteger>();

        // R[], S, Z
        contextVector = computeKeyContext(pk, contextVector);
        contextVector = computeGroupParamContext(gp, contextVector);
        return Utils.hashOf(gp.getSystemParams().getL_H(), contextVector);
    }

    /**
     * Compute the part of the context influenced by an issuer public key.
     * 
     * @return Context vector generated from the given public key.
     */
    public static final Vector<BigInteger> computeKeyContext(
            IssuerPublicKey pk, Vector<BigInteger> contextVector) {
        final BigInteger[] capR = pk.getCapR();

        // R[], S, Z
        contextVector.add(pk.getCapS());
        contextVector.add(pk.getCapZ());
        for (int i = 0; i < capR.length; i++) {
            contextVector.add(capR[i]);
        }

        return contextVector;
    }

    /**
     * Compute the part of the context influenced by the group parameters.
     * 
     * @return Context vector generated from the given group parameters.
     */
    public static final Vector<BigInteger> computeGroupParamContext(
            GroupParameters gp, Vector<BigInteger> contextVector) {

        // group parameters
        contextVector.add(gp.getG());
        contextVector.add(gp.getH());
        contextVector.add(gp.getRho());
        contextVector.add(gp.getCapGamma());

        return contextVector;
    }

    /**
     * Convenience method to select the e-value for the CL signature.
     * 
     * @param sp
     *            System parameters.
     * @return Random prime <tt>e</tt>.
     */
    public static BigInteger chooseE(final SystemParameters sp) {
        BigInteger e;
        /**
         * offset = 2^(l_e-1), e in [2^(l_e - 1).. 2^(l_e -1) + 2^(lPrime_e - 1)
         * means we can pick the randomness in the interval [0..2^(lPrime_e -
         * 1)] and then add the offset.
         */
        final BigInteger offset = BigInteger.ONE.shiftLeft(sp.getL_e() - 1);
        do {
            e = Utils.computeRandomNumber(sp.getL_ePrime() - 1);
            // add offset
            e = e.add(offset);
        } while (!e.isProbablePrime(sp.getL_pt()));
        return e;
    }

    /**
     * Computes a multi-base exponentiation with the bases as specified in the
     * group parameters. For example, this is used to compute the value of a
     * pseudonym.
     * 
     * @param gp
     *            Group parameters.
     * @param m
     *            Message value.
     * @param r
     *            Randomness.
     * 
     * @return <tt>g^m * h^r (mod capGamma)</tt>.
     */
    public static BigInteger computeCommitment(final GroupParameters gp,
            final BigInteger m, final BigInteger r) {

        final BigInteger g = gp.getG();
        final BigInteger h = gp.getH();
        final BigInteger gamma = gp.getCapGamma();

        BigInteger comm = null;
        comm = Utils.expMul(comm, g, m, gamma);
        comm = Utils.expMul(comm, h, r, gamma);

        return comm;
    }

    /**
     * Computes <tt>vTilde + c*v</tt>.
     * 
     * @param vTilde
     *            Random value.
     * @param c
     *            Challenge
     * @param v
     *            Original value.
     * @return <tt>vTilde + c*v</tt>.
     */
    public static BigInteger computeResponse(final BigInteger vTilde,
            final BigInteger c, final BigInteger v) {
        return vTilde.add(c.multiply(v));
    }

    /**
     * Choose a random number of length
     * <tt>l<sub>m</sub> + l<sub>Phi</sub> + l<sub>H</sub></tt>.
     * {@link SystemParameters SystemParameter class provides definition of
     * these lengths.}
     * 
     * @return Random value.
     */
    public static BigInteger getTildeRandom(final SystemParameters sp) {
        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
        return Utils.computeRandomNumberSymmetric(bitlength);
    }

    /**
     * Encodes a string such that it can be used as attribute value within a
     * credential.
     * 
     * @param l_H
     *            Length of a hash (as defined in the system parameters).
     * @param string
     *            String to be encoded.
     * @return BigInteger encoding the given string.
     */
    public static BigInteger encode(final int l_H, final String string) {
        return hashOf(l_H, string);
    }

    private static BigInteger hashOf(final int l_H, final String string) {
        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            log.log(Level.SEVERE, e1.getMessage(), e1);
            throw new RuntimeException(e1.getMessage());
        }

        // length in bytes
        int hashLen = l_H / BYTE_BIT_LENGTH;
        if (DIGEST_METHOD.equals("SHA-256")) {
            if (hashLen < SHA_BIT_LENGTH / BYTE_BIT_LENGTH) {
                log.log(Level.SEVERE, "SHA-256: hashLen < " + SHA_BIT_LENGTH
                        + "/" + BYTE_BIT_LENGTH + " (" + hashLen + ")");
                throw new RuntimeException("Digest error");
            }
        }

        byte[] byteArray = new byte[hashLen];
        try {
            byteArray = digest.digest(string.getBytes());
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error calculating hash of string: ", e);
            throw new RuntimeException("Digest error");
        }
        return new BigInteger(byteArray);
    }

    /**
     * @param pred
     *            Predicate defining the values that will be used and where the
     *            corresponding constants will be added.
     * @return Issuer public key where the constants are taken from.
     */
    public static IssuerPublicKey getPrimeEncodingConstants(
            final PrimeEncodePredicate pred) {
        AttributeStructure a = pred.getIdentifier().getAttStruct();
        IssuerPublicKey ipk = (IssuerPublicKey) StructureStore.getInstance()
                .get(pred.getIdentifier().getIssuerPublicKeyId());

        Iterator<String> iterator = pred.getAttributeNames().iterator();
        Vector<BigInteger> constants = new Vector<BigInteger>();
        while (iterator.hasNext()) {
            BigInteger constant = a.getPrimeFactor(iterator.next());
            if (constant == null) {
                throw new RuntimeException("Wrong description of a prime "
                        + "encoded attribute.");
            }
            constants.add(constant);
        }
        pred.setConstants(constants);
        return ipk;
    }

    /**
     * @param length
     *            Number of characters of the random string to be generated.
     * @return String with <code>length</code> characters.
     */
    public static String getRandomString(int length) {
        SecureRandom rand = new SecureRandom();
        return new BigInteger(length * 5, rand).toString(32);
    }
}
