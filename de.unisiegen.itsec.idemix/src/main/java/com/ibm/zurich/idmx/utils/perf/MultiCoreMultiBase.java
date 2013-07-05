/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;
import java.util.Vector;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;

import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * To compute the product of modular exponentiations on a multi-core setting.
 * The client builds a Vector<Exponentiation> and a set of worker threads then
 * computes the individual exponentiations and accumulates the resulting
 * product.
 * 
 * @see Exponentiation
 */
public class MultiCoreMultiBase {

    private final int nbrOfProcessors;

    /**
     * Accumulating the result of the partial product.
     */
    private static class Accumulator {

        // /**
        // * @return the modulus
        // */
        // public BigInteger getModulus() {
        // return modulus;
        // }

        private BigInteger val = BigInteger.ONE;
        private final BigInteger modulus;

        // Accumulator(final BigInteger mod) {
        // modulus = mod;
        // }

        /**
         * Constructor with initial value.
         * 
         * @param _val
         * @param mod
         */
        Accumulator(final BigInteger theValue, final BigInteger mod) {
            val = theValue;
            modulus = mod;
        }

        /**
         * To multiply-in one additional factor into the accumulated product.
         * 
         * @param fact
         *            factor. new value of accumulator is current value * factor
         *            mod( modulus).
         */
        synchronized void multiply(final BigInteger fact) {
            // this op must be atomic. And presumably, it's a hot-spot....
            if (this.val.equals(BigInteger.ONE)) {
                this.val = fact.mod(this.modulus);
            } else {
                this.val = this.val.multiply(fact).mod(this.modulus);
            }
        }

        /**
         * To get the accumulator's value.
         * 
         * @return accumulator value.
         */
        synchronized BigInteger getValue() {
            return this.val;
        }
    }

    /**
     * The working thread. We create one per core.
     */
    private static class ExponentiatorThread extends Thread {

        private boolean haveWork = false;
        private Accumulator result = null;
        private CountDownLatch latch = null;
        private ArrayBlockingQueue<Exponentiation> queue = null;

        ExponentiatorThread() {
            super();
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

                        Exponentiation exp = null;

                        // while queue is non empty; get a task to do
                        while ((exp = this.queue.poll()) != null) {

                            // System.err.println( "got task...");

                            // compute the exponentiation
                            final BigInteger res = exp
                                    .getExponentiator()
                                    .modPow(exp.getExponent(),
                                            exp.getExponentiator().getModulus());
                            // and multiply the result to the accumulator
                            this.result.multiply(res);
                        }

                        // queue is empty. we signal the master thread and go to
                        // sleep.
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
        synchronized boolean dispatch(
                final ArrayBlockingQueue<Exponentiation> queue,
                final Accumulator accu, final CountDownLatch latch) {
            this.queue = queue;
            this.result = accu;
            this.latch = latch;
            this.haveWork = true;
            // System.err.println( "notifying thread");
            this.notify();
            return true;
        }
    }

    /** The set of working threads. */
    private final ExponentiatorThread threads[];

    /**
     * Constructor.
     */
    private MultiCoreMultiBase() {
        // Check for the constant "USE_MULTI_CORE_EXP" was added as the threads
        // were created even if the constant was set to false and the simple
        // "compute" method was called.
        if (!Constants.USE_MULTI_CORE_EXP) {
            this.nbrOfProcessors = 1;
        } else {
            this.nbrOfProcessors = Runtime.getRuntime().availableProcessors();
        }

        if (this.nbrOfProcessors == 1) {
            this.threads = null;
            return;
        }

        this.threads = new ExponentiatorThread[this.nbrOfProcessors];
        for (int i = 0; i < this.nbrOfProcessors; i++) {
            this.threads[i] = new ExponentiatorThread();
            this.threads[i].start();
        }
    }

    private static MultiCoreMultiBase instance = new MultiCoreMultiBase();

    /**
     * To get the instance of multi-core multi-base exponentiator.
     * 
     * @return the instance.
     */
    public static MultiCoreMultiBase getInstance() {
        return instance;
    }

    /**
     * To compute the product sequentially.
     * 
     * @param accu
     * @param exponentiations
     * @param modulus
     * @return accu * product of exponentiations modulo( modulus).
     */
    public static BigInteger compute(BigInteger accu,
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {
        if (accu == null) {
            accu = BigInteger.ONE;
        }

        for (int i = 0; i < exponentiations.size(); i++) {
            final Exponentiation exp = exponentiations.get(i);

            assert (modulus.equals(exp.getExponentiator().getModulus()));

            // do the exponentiation
            final ModPow mp = exp.getExponentiator();

            final BigInteger res = mp
                    .modPow(exp.getExponent(), mp.getModulus());

            // and multiply the result to the accumulator
            accu = accu.multiply(res).mod(modulus);
        }
        return accu;
    }

    // public static BigInteger compute(BigInteger accu,
    // final Vector<Expo> exponentiations) {
    // if (accu == null) {
    // accu = BigInteger.ONE;
    // }
    // BigInteger base;
    // BigInteger exponent;
    // BigInteger modulus;
    // BigInteger res;
    // Expo exp;
    //
    // for (int i = 0; i < exponentiations.size(); i++) {
    // exp = exponentiations.get(i);
    // // TODO (pbi) assert that all moduli are equal
    //
    // base = exp.getBase();
    // exponent = exp.getExponent();
    // modulus = exp.getModulus();
    // res = base.modPow(exponent, modulus);
    //
    // // and multiply the result to the accumulator
    // accu = accu.multiply(res).mod(modulus);
    // }
    // return accu;
    // }

    public static BigInteger compute(
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {
        return compute(BigInteger.ONE, exponentiations, modulus);
    }

    /**
     * Computes the product of the individual exponentiations, all modulo(
     * modulus).
     * 
     * @param initialAccuVal
     *            initial accumulator value.
     * @param exponentiations
     *            set of modular exponentiations.
     * @param modulus
     * @return product of exponentiations times accuVal modulo( modulus).
     */
    public BigInteger multiBaseExp(BigInteger initialAccuVal,
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {

        // log.log(Level.INFO, "# of expos: " + exponentiations.size());

        if (initialAccuVal == null) {
            initialAccuVal = BigInteger.ONE;
        }
        if (this.nbrOfProcessors == 1) {
            return compute(initialAccuVal, exponentiations, modulus);
        } else if (exponentiations.size() == 1) {
            return compute(initialAccuVal, exponentiations, modulus);
        } else { // use the multi-core set-up.
            final Accumulator accu = new Accumulator(initialAccuVal, modulus);
            // create the queue
            final ArrayBlockingQueue<Exponentiation> queue = new ArrayBlockingQueue<Exponentiation>(
                    exponentiations.size(), true, exponentiations);
            // create the count-down latch
            final CountDownLatch latch = new CountDownLatch(
                    this.nbrOfProcessors);

            // dispatch the working threads
            for (int i = 0; i < this.threads.length; i++) {
                final ExponentiatorThread t = this.threads[i];
                t.dispatch(queue, accu, latch);
            }

            // we wait until the queue has been processed. The accumulator
            // contains the result.
            try {
                latch.await();
            } catch (InterruptedException ie) {
                ie.printStackTrace();
                throw new RuntimeException();
            }
            return accu.getValue();
        }

    }

    /**
     * To compute the product of the set of modular exponentiations.
     * 
     * @param exponentiations
     *            set of modular exponentiations.
     * @param modulus
     * @return product of modular exponentiations.
     */
    public BigInteger multiBaseExp(
            final Vector<Exponentiation> exponentiations,
            final BigInteger modulus) {
        // initial value defaults to 1.
        return this.multiBaseExp(BigInteger.ONE, exponentiations, modulus);
    }

    /** for fixed-base comb method; how many rows do we have in exponent array. */
    static private final int ROWS_IN_EXPO_ARR = 5;

    /**
     * for fixed-base comb method; how many columns do we have in lookup table
     * G[][]? This is the v parameter to the algorithm, 0 <= v <= ceil((t+1)/a).
     */
    static private final int NBR_OF_COLS_IN_G = 8;

    private final static int EXPO_WIDTH = 512;

    private final static int NBR_ITER = 500;

    public static void main(String args[]) {

        BigInteger base1 = Utils.computeRandomNumber(EXPO_WIDTH);
        BigInteger base2 = Utils.computeRandomNumber(EXPO_WIDTH);

        final BigInteger modulus = new BigInteger(
                "27278151779216340057325220772965141946162399060765329594977520000890688564506779182200478096353227987986977667789871417199243892821722167935182204861383080156379623229199441628377162482407702418636985589003903685403437786394245755585464491336163572457000210948602479884045898479129592906458620039542042606320928640280023828527355136383982650852218929244432025524650151437413386111947158572706793336337473850623024811748352441347496425190741803691060085635607510766738830315852677846821923554679807853876246511247827196905264528171135439034582733174563976208627728793720715425567989111541464298650319520509158746387041");

        final ModPow mpw[] = new ModPow[2];

        // mpw[0] = new DefModPow( base1, modulus);
        // mpw[1] = new DefModPow( base2, modulus);

        mpw[0] = new FixedBaseComb(base1, EXPO_WIDTH, ROWS_IN_EXPO_ARR,
                NBR_OF_COLS_IN_G, modulus);
        mpw[1] = new FixedBaseComb(base2, EXPO_WIDTH, ROWS_IN_EXPO_ARR,
                NBR_OF_COLS_IN_G, modulus);

        // final MultiCoreMultiBase mcmb = new MultiCoreMultiBase();

        long t1 = System.currentTimeMillis();
        for (int i = 0; i < NBR_ITER; i++) {

            // System.err.println( "step " + i);

            final BigInteger exponents[] = new BigInteger[2];
            exponents[0] = Utils.computeRandomNumber(EXPO_WIDTH);
            exponents[1] = Utils.computeRandomNumber(EXPO_WIDTH);

            final Vector<Exponentiation> expos = new Vector<Exponentiation>();
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));

            // final BigInteger result = mcmb.multiBaseExp(expos, modulus);

            // verification of results
            /*
             * final Accumulator accu = new Accumulator( modulus);
             * MultiCoreMultiBase2.compute(accu, expos, modulus); assert(
             * result.equals( accu.getValue()));
             */

        }
        long t2 = System.currentTimeMillis();

        long t3 = System.currentTimeMillis();
        for (int i = 0; i < NBR_ITER; i++) {

            // System.err.println( "step " + i);

            final BigInteger exponents[] = new BigInteger[2];
            exponents[0] = Utils.computeRandomNumber(EXPO_WIDTH);
            exponents[1] = Utils.computeRandomNumber(EXPO_WIDTH);

            final Vector<Exponentiation> expos = new Vector<Exponentiation>();
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));

            MultiCoreMultiBase.compute(expos, modulus);
        }
        long t4 = System.currentTimeMillis();

        mpw[0] = new DefModPow(base1, modulus);
        mpw[1] = new DefModPow(base2, modulus);

        long t5 = System.currentTimeMillis();
        for (int i = 0; i < NBR_ITER; i++) {

            // System.err.println( "step " + i);

            final BigInteger exponents[] = new BigInteger[2];
            exponents[0] = Utils.computeRandomNumber(EXPO_WIDTH);
            exponents[1] = Utils.computeRandomNumber(EXPO_WIDTH);

            final Vector<Exponentiation> expos = new Vector<Exponentiation>();
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));
            expos.add(new Exponentiation(mpw[0], exponents[0]));
            expos.add(new Exponentiation(mpw[1], exponents[1]));

            MultiCoreMultiBase.compute(expos, modulus);
        }
        long t6 = System.currentTimeMillis();

        System.err.println("multi-core, comb: " + (t2 - t1));
        System.err.println("single-core, comb: " + (t4 - t3));
        System.err.println("single-core, default: " + (t6 - t5));
    }
}
