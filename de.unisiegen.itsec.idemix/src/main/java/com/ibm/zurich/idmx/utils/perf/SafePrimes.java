/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.CountDownLatch;

import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Utils;

/**
 *
 */
public class SafePrimes {

    /** controls usage of identical seed for every run. */
    private final static boolean DEVELOPING = false;

    /** initial random seed value, if DEVELOPING. */
    private final static int SEED = 123;

    private static SecureRandom statRandom;
    static {
        // we generate a unique random nbr generator and use
        // it throughout the lib. in case of developing, we
        // set the seed to a fixed value so that things are deterministic.
        try {
            statRandom = SecureRandom.getInstance("SHA1PRNG");
            if (DEVELOPING) {
                statRandom.setSeed(SEED);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            statRandom = null;
        }
    }

    private static class PrimeResult {

        private BigInteger result = null;

        PrimeResult() {
            super();
        }

        synchronized void setResult(final BigInteger r) {
            this.result = r;
        }

        synchronized BigInteger getResult() {
            return this.result;
        }

    }

    private static class TaskDescriptor {

        PrimeResult result;
        final int bitLength;
        final int primeCertainty;
        final BigInteger primeBound;

        TaskDescriptor(final PrimeResult result, final int bitLength,
                final BigInteger primeBound, final int primeCertainty) {
            this.result = result;
            this.bitLength = bitLength;
            this.primeBound = primeBound;
            this.primeCertainty = primeCertainty;
        }

    }

    /**
     * The working thread. We create one per core.
     */
    private static class IterationThread extends Thread {

        private boolean haveWork = false;
        private CountDownLatch latch = null;
        private TaskDescriptor task = null;
        private SecureRandom random = null;

        IterationThread() throws NoSuchAlgorithmException {
            super();
            this.random = statRandom; // SecureRandom.getInstance("SHA1PRNG");
        }

        /**
         * Thread's main loop.
         */
        public void run() {
            while (true) {
                try {
                    synchronized (this) {

                        // System.err.println( "thread: going to wait...");

                        while (!this.haveWork)
                            this.wait();

                        // System.err.println( "thread " + this.toString() +
                        // ": " + this.task.nbrIterations);

                        // we quit after the nbr of iterations OR if some other
                        // thread has detected a non-prime.
                        while (this.task.result.getResult() == null) {
                            final BigInteger p = iterationStep(
                                    this.task.bitLength, this.task.primeBound,
                                    this.task.primeCertainty, this.random);
                            if (p != null) {
                                // System.err.println( "found result");
                                this.task.result.setResult(p);
                                break;
                            }
                        }

                        // task is completed.
                        this.haveWork = false;
                        this.latch.countDown();
                    }

                } catch (InterruptedException ie) {
                    ie.printStackTrace();
                }
            }
        }

        /**
         * To dispatch a queue of exponentiations onto the worker thread.
         * 
         * @param queue
         *            set of exponentiation tasks.
         * @param accu
         *            the result accumulator.
         * @param latch
         *            synchronization with master thread.
         * @return success/failures.
         */
        synchronized boolean dispatch(final TaskDescriptor task,
                final CountDownLatch latch) {
            this.task = task;
            this.latch = latch;
            this.haveWork = true;
            // System.err.println( "notifying thread");
            this.notify();
            return true;
        }

    }

    // pre-compute a list of small primes
    private static final int MAX_SMALL_PRIME = 16384;

    protected final static List<BigInteger> listOfSmallPrimes = generateSmallPrimes(
            MAX_SMALL_PRIME, 3);

    /**
     * This method generates small prime numbers up to a specified bounds using
     * the Sieve of Eratosthenes algorithm.
     * 
     * @param primeBound
     *            The upper bound for the primes to be generated
     * @param startingPrime
     *            The first prime in the list of primes that is returned
     * @return List of primes up to the specified bound. Each prime is a
     *         APInteger object.
     */
    public static ArrayList<BigInteger> generateSmallPrimes(
            final int primeBound, int startingPrime) {
        final ArrayList<BigInteger> res = new ArrayList<BigInteger>();
        if ((primeBound <= 1) || (startingPrime > primeBound))
            return res;
        if (startingPrime <= 2) {
            startingPrime = 2;
            res.add(Utils.TWO);
        }
        boolean[] primes = new boolean[(int) ((primeBound - 1) / 2)];
        int i, k, prime;
        for (i = 0; i < primes.length; i++)
            primes[i] = true;
        for (i = 0; i < primes.length; i++) {
            if (primes[i]) {
                prime = 2 * i + 3;
                for (k = i + prime; k < primes.length; k += prime)
                    primes[k] = false;
                if (prime >= startingPrime)
                    res.add(BigInteger.valueOf(prime));
            }
        }
        return res;
    }

    /**
     * Test whether the provided pDash or p = 2*pDash + 1 are divisible by any
     * of the small primes saved in the listOfSmallPrimes. A limit for the
     * largest prime to be tested against can be specified, but it will be
     * ignored if it exceeds the number of pre-computed primes.
     * 
     * @param pDash
     *            The number to be tested (pDash)
     * @param primeBound
     *            The limit for the small primes to be tested against.
     */
    private static boolean testSmallPrimeFactors(final BigInteger pDash,
            final BigInteger primeBound) {
        ListIterator<BigInteger> primes = listOfSmallPrimes.listIterator();
        BigInteger smallPrime = BigInteger.ONE;

        while (primes.hasNext() && (smallPrime.compareTo(primeBound) < 0)) {
            smallPrime = (BigInteger) primes.next();

            // r = pDash % smallPrime
            final BigInteger r = pDash.remainder(smallPrime);

            // test if pDash = 0 (mod smallPrime)
            // if (r.compareTo(BigInteger.ZERO) == 0) {
            if (r.equals(BigInteger.ZERO)) {
                return false;
            }
            // test if p == 0 (mod smallPrime) (or, equivalently, r ==
            // smallPrime - r - 1)
            if (r.compareTo(smallPrime.subtract(r).subtract(BigInteger.ONE)) == 0) {
                return false;
            } else {
            }
        }
        return true;
    }

    /**
     * Tests if A is a Miller-Rabin witness for N
     * 
     * @param A
     *            Number which is supposed to be the witness
     * @param N
     *            Number to be tested against
     * @return true if A is Miller-Rabin witness for N, false otherwise
     */
    public static boolean isMillerRabinWitness(final BigInteger A,
            final BigInteger N) {
        BigInteger N_1 = N.subtract(BigInteger.ONE);
        int t = 0;

        while (N_1.divide(Utils.TWO.pow(t)).mod(Utils.TWO)
                .compareTo(BigInteger.ZERO) == 0)
            t++;
        final BigInteger U = N_1.divide(Utils.TWO.pow(t));

        BigInteger x0;
        BigInteger x1 = A.modPow(U, N);

        for (int i = 0; i < t; i++) {
            x0 = x1;
            x1 = x0.modPow(Utils.TWO, N);
            if (x1.compareTo(BigInteger.ONE) == 0
                    && x0.compareTo(BigInteger.ONE) != 0
                    && x0.compareTo(N_1) != 0)
                return true;
        }
        if (x1.compareTo(BigInteger.ONE) != 0)
            return true;
        else
            return false;
    }

    private static BigInteger iterationStep(final int bitLength,
            final BigInteger primeBound, final int primeCertainty,
            final SecureRandom random) {

        // System.err.println( ".");

        // generate random, odd pDash
        final BigInteger pDash = Utils
                .randomOddBigNumber(bitLength - 1, random);

        // calculate p = 2*pDash+1
        final BigInteger p = pDash.shiftLeft(1).add(BigInteger.ONE);

        // test if pDash or p are divisible by some small primes
        if (!testSmallPrimeFactors(pDash, primeBound)) {
            return null;
        }
        // test if 2 is a compositness witness for pDash or p
        if (isMillerRabinWitness(Utils.TWO, pDash)) {
            return null;
        }

        // FIXME: does this ensure that p is prime? otherwise we need to add
        // such a test!!! (jorn)
        // test if 2^(pDash) == +1/-1 (mod p)
        final BigInteger tempP = Utils.TWO.modPow(pDash, p);
        if ((tempP.compareTo(BigInteger.ONE) != 0)
                && (tempP.compareTo(p.subtract(BigInteger.ONE)) != 0))
            return null;

        // use the BigInteger primality check, implements MillerRabin
        // and LucasLehmer
        if (pDash.isProbablePrime(primeCertainty)) { // we found a prime!
            // and return p = 2*p' + 1
            return p;
        }
        return null;
    }

    private boolean forceSingleThread = false;

    public final void setForceSingleThread(boolean flag) {
        this.forceSingleThread = flag;
    }

    private static BigInteger getPrimeBound(int bitLength) {
        // some heuristic checks to limit the number of small primes
        // to check against and the number of Miller-Rabin primality tests at
        // the end
        if (bitLength <= 256) {
            return BigInteger.valueOf(768);
        } else if (bitLength <= 512) {
            return BigInteger.valueOf(3072);
        } else if (bitLength <= 768) {
            return BigInteger.valueOf(6144);
        } else if (bitLength <= 1024) {
            return BigInteger.valueOf(10240);
        } else {
            return BigInteger.valueOf(MAX_SMALL_PRIME + 1);
        }
    }

    /**
     * The main method to compute a random safe prime of the specified bit
     * length. IMPORTANT: The computed prime will have two first bits and the
     * last bit set to 1 !! i.e. > (2^(bitLength-1)+2^(bitLength-2)+1). This is
     * done to be sure that if two primes of bitLength n are multiplied, the
     * result will have the bitLength of 2*n exactly.
     * 
     * This implementation uses the algorithm proposed by Ronald Cramer and
     * Victor Shoup in "Signature Schemes Based on the strong RSA Assumption"
     * May 9, 2000.
     * 
     * @param bitLength
     *            The bit length of the safe prime to be computed.
     * @param primeCertainty
     *            The error probability that the computed number is not prime is
     *            (2^(-primeCertainty))
     * @return A prime number p which is considered to be safe with the prime
     *         certainty specified above. It has the property of p = 2p'+ 1 with
     *         both, p and p' being prime.
     */
    public final BigInteger genSafePrime(final int bitLength,
            final int primeCertainty) {

        final BigInteger primeBound = getPrimeBound(bitLength);

        BigInteger p = null;
        if (this.forceSingleThread || this.nbrOfProcessors == 1) {
            do {
                p = iterationStep(bitLength, primeBound, primeCertainty,
                        statRandom);
            } while (p == null);
        } else {
            final CountDownLatch latch = new CountDownLatch(
                    this.nbrOfProcessors);
            final PrimeResult pr = new PrimeResult();
            final TaskDescriptor td = new TaskDescriptor(pr, bitLength,
                    primeBound, primeCertainty);

            // lauch the worker threads
            for (int i = 0; i < this.nbrOfProcessors; i++) {
                this.threads[i].dispatch(td, latch);
            }
            // and wait until they're done.

            try {
                latch.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }

            p = pr.getResult();
            assert (p != null);
        }

        /*
         * do { // generate random, odd pDash pDash =
         * randomOddBigNumber(bitLength - 1);
         * 
         * // calculate p = 2*pDash+1 p =
         * pDash.shiftLeft(1).add(BigInteger.ONE);
         * 
         * // test if pDash or p are divisible by some small primes if
         * (!testSmallPrimeFactors(pDash, primeBound)) { continue; } // test if
         * 2 is a compositness witness for pDash or p if
         * (isMillerRabinWitness(Utils.TWO, pDash)) { continue; }
         * 
         * // test if 2^(pDash) == +1/-1 (mod p) tempP = Utils.TWO.modPow(pDash,
         * p); if ((tempP.compareTo(BigInteger.ONE) != 0) &&
         * (tempP.compareTo(p.subtract(BigInteger.ONE)) != 0)) continue;
         * 
         * // use the BigInteger primality check, implements MillerRabin // and
         * LucasLehmer if (pDash.isProbablePrime(primeCertainty)) { stop = true;
         * } } while (!stop);
         */

        return p;
    }

    /** nbr of cores */
    private final int nbrOfProcessors;

    /** one thread per core */
    private final IterationThread threads[];

    /**
     * Constructor.
     * 
     * @throws NoSuchAlgorithmException
     */
    private SafePrimes() throws NoSuchAlgorithmException {
        super();

        if (statRandom == null) {
            throw new NoSuchAlgorithmException();
        }
        // Check for the constant "USE_MULTI_CORE_SAFE_PRIMES" was added as the
        // threads
        // were created even if the constant was set to false and the simple
        // "compute" method was called.
        if (!Constants.USE_MULTI_CORE_SAFE_PRIMES) {
            this.nbrOfProcessors = 1;
        } else {
            this.nbrOfProcessors = Runtime.getRuntime().availableProcessors();
        }

        if (this.nbrOfProcessors == 1) {
            this.threads = null;
            return;
        }

        this.threads = new IterationThread[this.nbrOfProcessors];
        for (int i = 0; i < this.nbrOfProcessors; i++) {
            this.threads[i] = new IterationThread();
            this.threads[i].start();
        }
    }

    /** singleton instance. */
    private static SafePrimes instance = null;

    static {
        try {
            instance = new SafePrimes();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            instance = null;
        }
    }

    public static SafePrimes getInstance() {
        return instance;
    }

    private static final int BIT_LENGTH = 1024;
    private static final int CERTAINTY = 80;
    private static final int NBR_ITER = 50;

    public static void main(String args[]) {

        final SafePrimes sp = SafePrimes.getInstance();

        long t1 = System.currentTimeMillis();
        for (int i = 0; i < NBR_ITER; i++) {
            final BigInteger p = sp.genSafePrime(BIT_LENGTH, CERTAINTY);

            System.err.println(p.toString());
        }
        long t2 = System.currentTimeMillis();

        sp.setForceSingleThread(true);

        long t3 = System.currentTimeMillis();
        for (int i = 0; i < NBR_ITER; i++) {
            final BigInteger p = sp.genSafePrime(BIT_LENGTH, CERTAINTY);

            System.err.println(p.toString());
        }
        long t4 = System.currentTimeMillis();

        System.err.println("multi-core: " + (t2 - t1) / NBR_ITER);
        System.err.println("built-in: " + (t4 - t3) / NBR_ITER);
    }
}
