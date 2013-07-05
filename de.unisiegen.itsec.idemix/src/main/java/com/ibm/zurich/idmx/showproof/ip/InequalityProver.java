/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.ip;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Vector;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * The Idemix range prover, prover side.
 * 
 * @see InequalityVerifier
 */
public class InequalityProver {

    /** Logger. */
    private static Logger log = Logger.getLogger(InequalityProver.class
            .getName());

    /** General prover. */
    private final Prover prover;
    /** Inequality predicate. */
    private final InequalityPredicate pred;

    /** Delta value which is represented as the sum of four squares. */
    private final BigInteger delta;
    /** Four squares. */
    private final BigInteger[] uValues;

    /** Number of squares that the given number is decomposed into. */
    public static int NUM_SQUARES = 4;

    private final BigInteger tValues[] = new BigInteger[NUM_SQUARES + 1];
    private final BigInteger rValues[] = new BigInteger[NUM_SQUARES + 1];
    private final BigInteger rTildeValues[] = new BigInteger[NUM_SQUARES + 1];
    private final BigInteger uTildeValues[] = new BigInteger[NUM_SQUARES + 1];

    private BigInteger alpha;

    private BigInteger alphaTilde;
    /** Sign value. -1 if * is <= or <; +1 if * is >= or >. */
    private BigInteger a;

    /** Convenience: Key used for the proof. */
    private final IssuerPublicKey pk;

    /**
     * Constructor. In case of the comparison failing, we set the status to a
     * failure value. The client must test this!
     * 
     * @param theProver
     *            Inequality prover.
     * @param inequalityPredicate
     *            Inequality predicate.
     */
    public InequalityProver(final Prover theProver,
            final InequalityPredicate inequalityPredicate) {
        super();
        prover = theProver;
        pred = inequalityPredicate;

        pk = pred.getKey();

        // [spec: ProveInequality 1.] this also sets a
        delta = computeDelta();
        if (delta.compareTo(BigInteger.ZERO) < 0) {
            throw new RuntimeException("Inequality does not hold: "
                    + pred.getFirstArgumentValue() + Constants.DELIMITER
                    + pred.getName());
        }

        // [spec: ProveInequality 1.2] express delta as sum of four squares
        log.log(Level.FINE, "RS decomposing delta....");
        uValues = DecompRS.decomposeInteger(prover.getSysParams(), delta);
        log.log(Level.FINE, "RS decomposition done.");

        // [spec: ProveInequality 1.3] compute T values; setting rValues in the
        // process.
        computeTValues();
    }

    /**
     * To compute the delta value.
     * 
     * @return delta value. delta can be < 0.
     */
    private BigInteger computeDelta() {
        // [spec: ProveInequality 1.1]
        BigInteger tempDelta = BigInteger.ZERO;
        switch (pred.getOperator()) {
        // Note that case statements are only left when upon the first 'break'
        // statment (i.e., the sequence of computing is changes w.r.t. the
        // specification).
        case LT:
            // m_r - m - 1
            tempDelta = tempDelta.subtract(BigInteger.ONE);
        case LEQ:
            // a = -1
            a = BigInteger.ONE.negate();

            // m_r - m: const - attr1 or attr2 - attr1
            tempDelta = tempDelta.add(pred.getSecondArgument());
            tempDelta = tempDelta.subtract(pred.getFirstArgumentValue());
            break;
        case GT:
            // m - m_r - 1
            tempDelta = tempDelta.subtract(BigInteger.ONE);
        case GEQ:
            // a = 1
            a = BigInteger.ONE;

            // m - m_r: attr1 - const or attr1 - attr2
            tempDelta = tempDelta.add(pred.getFirstArgumentValue());
            tempDelta = tempDelta.subtract(pred.getSecondArgument());
            break;
        default:
            throw new RuntimeException("Inequality operator not implemented.");
        }
        return tempDelta;
    }

    /**
     * To generate the randomness in computing the T values.
     * 
     * @param sp
     *            System parameters.
     * @return random number.
     */
    private static BigInteger genRandom(final SystemParameters sp) {
        int bitlength = sp.getL_n() + sp.getL_Phi();
        return Utils.computeRandomNumber(bitlength);
    }

    /**
     * To compute the T value.
     * 
     * @param capZ
     *            First base of the exponentiation.
     * @param capS
     *            Second base of the exponentiation.
     * @param n
     *            Modulus.
     * @param u
     *            First exponent.
     * @param r
     *            Second exponent.
     * @return <tt>capZ^u * capS^r (mod n)</tt>.
     */
    private static BigInteger computeTValue(final BigInteger capZ,
            final BigInteger capS, final BigInteger n, final BigInteger u,
            final BigInteger r) {

        assert (capZ != null);
        assert (capS != null);
        assert (n != null);
        assert (u != null);
        assert (r != null);

        final Vector<Exponentiation> e = new Vector<Exponentiation>();
        e.add(new Exponentiation(capZ, u, n));
        e.add(new Exponentiation(capS, r, n));
        return Utils.multiExpMul(e, n);
    }

    private void computeTValues() {
        final BigInteger n = pk.getN();
        final BigInteger capZ = pk.getCapZ();
        final BigInteger capS = pk.getCapS();

        for (int i = 0; i <= NUM_SQUARES; i++) {
            rValues[i] = genRandom(pk.getGroupParams().getSystemParams());
        }

        for (int i = 0; i < NUM_SQUARES; i++) {
            tValues[i] = computeTValue(capZ, capS, n, uValues[i], rValues[i]);
        }
        // compute the delta related t-value.
        tValues[NUM_SQUARES] = computeTValue(capZ, capS, n, delta,
                rValues[NUM_SQUARES]);
    }

    private BigInteger computeAlpha() {
        BigInteger alpha = rValues[NUM_SQUARES];
        for (int j = 0; j < NUM_SQUARES; j++) {
            // u_j * r_j
            final BigInteger ur = uValues[j].multiply(rValues[j]);
            // alpha = alpha - u_j*r_j
            alpha = alpha.subtract(ur);
        }
        return alpha;
    }

    /**
     * To generate randomness for uTilde and rTilde.
     * 
     * @param sp
     *            System parameters.
     * @param attributeLength
     *            Bitlength of the attribute the randomness is generated for.
     * @param nPhi
     *            multiplier of l_Phi
     * @return random value.
     */
    private static BigInteger genTildeRandom(final SystemParameters sp,
            int attributeLength, int nPhi) {
        int bitlength = attributeLength + sp.getL_H() + nPhi * sp.getL_Phi();
        return Utils.computeRandomNumber(bitlength);
    }

    /**
     * Generate alphaTilde randomness.
     * 
     * @param sp
     *            System parameters.
     * @return random value.
     */
    private static BigInteger genAlphaTilde(final SystemParameters sp) {
        int bitlength = sp.getL_n() + sp.getL_m() + 2 * sp.getL_k() + 2
                * sp.getL_Phi() + 3;
        return Utils.computeRandomNumber(bitlength);
    }

    /**
     * @param capS
     *            Randomization base <tt>S</tt>
     * @param alphaTilde
     * @param n
     *            Modulus.
     * @return <tt>Q</tt>.
     */
    private BigInteger computeCapQ(final BigInteger capS,
            final BigInteger alphaTilde, final BigInteger n) {

        Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(capS, alphaTilde, n));
        for (int i = 0; i < NUM_SQUARES; i++) {
            expos.add(new Exponentiation(tValues[i], uTildeValues[i], n));
        }
        return Utils.multiExpMul(expos, n);
    }

    /**
     * @return THat values plus capQ and puts them onto the overall proof's
     *         t-values as well as adding T-values onto proof's common.
     */
    public final Vector<BigInteger> computeTHatValues() {

        Vector<BigInteger> localTValues = new Vector<BigInteger>();

        final BigInteger n = pk.getN();
        final BigInteger capZ = pk.getCapZ();
        final BigInteger capS = pk.getCapS();
        SystemParameters sp = pk.getGroupParams().getSystemParams();

        // generate the rTilde & rTildeDelta
        for (int i = 0; i <= NUM_SQUARES; i++) {
            rTildeValues[i] = genTildeRandom(sp, sp.getL_n(), 2);
        }

        // allocate storage.
        BigInteger[] tHat = new BigInteger[NUM_SQUARES + 1];

        // compute THat_i
        for (int i = 0; i < NUM_SQUARES; i++) {
            uTildeValues[i] = genTildeRandom(sp, sp.getL_m(), 1);
            tHat[i] = computeTValue(capZ, capS, n, uTildeValues[i],
                    rTildeValues[i]);
        }

        // special case for THat_Delta
        final BigInteger sPowerA = Utils.modPow(capS, a, n);
        // use mTilde of the relevant attribute.
        final BigInteger mTilde = pred.getFirstArgumentRandom();

        if (mTilde == null) {
            throw new RuntimeException("Identifier does not have a "
                    + "corresponding randomness. Probably you are "
                    + "proving an inequality w.r.t. a revealed "
                    + "attribute!?");
        }
        tHat[NUM_SQUARES] = computeTValue(capZ, sPowerA, n, mTilde,
                rTildeValues[NUM_SQUARES]);

        // compute capQ
        alphaTilde = genAlphaTilde(pk.getGroupParams().getSystemParams());
        final BigInteger capQ = computeCapQ(capS, alphaTilde, n);

        // output the t-values and the common values.
        // Note the order is relevant and must be respected in verification.
        // Note also that we append the common values in order T1..T4, TDelta.
        for (int i = 0; i <= NUM_SQUARES; i++) {
            localTValues.add(tHat[i]);
            prover.appendCommonValue(pred.getName() + Constants.DELIMITER + i,
                    tValues[i]);
        }
        // capQ is only appended to the t-values.
        localTValues.add(capQ);
        return localTValues;
    }

    /**
     * @param c
     *            Challenge.
     * @return S-values which are appended to prover's s-values.
     */
    public final HashMap<String, SValue> computeSValues(final BigInteger c) {

        HashMap<String, SValue> localSValues = new HashMap<String, SValue>();

        final BigInteger[] uHat = new BigInteger[NUM_SQUARES + 1];
        final BigInteger[] rHat = new BigInteger[NUM_SQUARES + 1];

        // Note that we do not send the mHat value as this needs to be taken
        // from the CL proof.
        for (int i = 0; i < NUM_SQUARES; i++) {
            // [spec: InequalityProver 3.1]
            rHat[i] = Utils.computeResponse(rTildeValues[i], c, rValues[i]);
            uHat[i] = Utils.computeResponse(uTildeValues[i], c, uValues[i]);
        }

        // [spec: InequalityProver 3.2] compute rHat_Delta
        rHat[NUM_SQUARES] = Utils.computeResponse(rTildeValues[NUM_SQUARES], c,
                rValues[NUM_SQUARES]);

        // [spec: ProveInequality 3.3] compute alpha
        alpha = computeAlpha();
        final BigInteger alphaHat = Utils.computeResponse(alphaTilde, c, alpha);

        localSValues.put(pred.getName(), new SValue(new SValuesIP(uHat, rHat,
                alphaHat)));
        return localSValues;
    }

}
