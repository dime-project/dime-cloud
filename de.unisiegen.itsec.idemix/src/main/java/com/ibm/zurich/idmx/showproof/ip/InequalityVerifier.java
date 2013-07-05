/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.ip;

import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * The Idemix range prover, verifier side.
 * 
 * @see InequalityProver
 */
public class InequalityVerifier {

    /** General verifier. */
    private final Verifier verifier;
    /** Inequality predicate. */
    private final InequalityPredicate pred;
    /** Difference of actual value and revealed value. */
    private final BigInteger capDeltaPrime;
    /** Sign value. -1 if * is <= or <; +1 if * is >= or >. */
    private BigInteger a;

    /**
     * @param theVerifier
     *            Verifier using this sub-verifier.
     * @param predicate
     *            Inequality predicate defining what has to be verified.
     */
    public InequalityVerifier(final Verifier theVerifier,
            final InequalityPredicate predicate) {
        verifier = theVerifier;
        pred = predicate;
        capDeltaPrime = computeDeltaPrime();
    }

    /**
     * @return Delta value.
     */
    private BigInteger computeDeltaPrime() {

        // [spec: ProveInequality 1.]
        BigInteger theDeltaPrime = pred.getSecondArgument();

        switch (pred.getOperator()) {
        case LT:
            // m_r - 1
            theDeltaPrime = theDeltaPrime.subtract(BigInteger.ONE);
        case LEQ:
            // a = -1
            a = BigInteger.ONE.negate();
            break;
        case GT:
            // m_r + 1
            theDeltaPrime = theDeltaPrime.add(BigInteger.ONE);
        case GEQ:
            // a = 1
            a = BigInteger.ONE;
            break;
        default:
            throw new RuntimeException("Inequality operator not implemented.");
        }
        return theDeltaPrime;
    }

    private static BigInteger computeTHat(final BigInteger t,
            final BigInteger negC, final BigInteger Z, final BigInteger uHat,
            final BigInteger S, final BigInteger rHat, final BigInteger n) {

        final Vector<Exponentiation> e = new Vector<Exponentiation>();
        e.add(new Exponentiation(t, negC, n));
        e.add(new Exponentiation(Z, uHat, n));
        e.add(new Exponentiation(S, rHat, n));
        return Utils.multiExpMul(e, n);

    }

    private static BigInteger computeTHatDelta(final BigInteger capT_Delta,
            final BigInteger a, final BigInteger capZ,
            final BigInteger capDeltaPrime, final BigInteger negC,
            final BigInteger mHat, final BigInteger capS,
            final BigInteger rHat_Delta, final BigInteger n) {

        final BigInteger sPowerA = Utils.modPow(capS, a, n);

        BigInteger tHatDelta = null;

        Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(capT_Delta, a, n));
        expos.add(new Exponentiation(capZ, capDeltaPrime, n));

        tHatDelta = Utils.multiExpMul(expos, n);

        tHatDelta = Utils.modPow(tHatDelta, negC, n);

        // e = new Vector<Exponentiation>();
        expos.set(0, new Exponentiation(capZ, mHat, n));
        expos.set(1, new Exponentiation(sPowerA, rHat_Delta, n));
        tHatDelta = Utils.multiExpMul(tHatDelta, expos, n);

        return tHatDelta;
    }

    private static BigInteger computeCapQHat(final BigInteger capT[],
            final BigInteger negC, final BigInteger uHat[],
            final BigInteger capS, final BigInteger alphaHat, final BigInteger n) {

        final Vector<Exponentiation> e = new Vector<Exponentiation>();

        e.add(new Exponentiation(capT[InequalityProver.NUM_SQUARES], negC, n));

        for (int i = 0; i < 4; i++) {
            e.add(new Exponentiation(capT[i], uHat[i], n));
        }

        e.add(new Exponentiation(capS, alphaHat, n));

        return Utils.multiExpMul(e, n);

    }

    /**
     * @param s
     *            S-values.
     * @return <tt>tHat</tt> values for the inequality proof.
     */
    public final Vector<BigInteger> computeTHatValues(final SValuesIP s) {

        assert (s != null);

        Vector<BigInteger> localTHatValues = new Vector<BigInteger>();

        final IssuerPublicKey pk = pred.getKey();
        final BigInteger n = pk.getN();
        final BigInteger capZ = pk.getCapZ();
        final BigInteger capS = pk.getCapS();

        final BigInteger negC = verifier.getNegC();

        final BigInteger[] tHat = new BigInteger[5];
        final BigInteger[] tValues = new BigInteger[5];

        // the common values for the range proof are T1, T2, .. T4, TDelta.
        for (int i = 0; i <= InequalityProver.NUM_SQUARES; i++) {
            String tValueName = pred.getName() + Constants.DELIMITER + i;
            tValues[i] = verifier.getCommonValRP(tValueName);
            if (tValues[i] == null) {
                throw new RuntimeException("Could not retrieve t-value: "
                        + tValueName);
            }
        }

        // Note that the mHat value is added by the verifier using the value
        // from the CL proof.
        final BigInteger mHat = s.getUHat()[InequalityProver.NUM_SQUARES];
        final BigInteger rDeltaHat = s.getRHat()[InequalityProver.NUM_SQUARES];

        // [spec: InequalityProver 2.1]
        final BigInteger capT_Delta = tValues[InequalityProver.NUM_SQUARES];
        tHat[InequalityProver.NUM_SQUARES] = computeTHatDelta(capT_Delta, a, capZ,
                capDeltaPrime, negC, mHat, capS, rDeltaHat, n);

        // [spec: InequalityProver 2.2]
        for (int i = 0; i < InequalityProver.NUM_SQUARES; i++) {
            final BigInteger uHat = s.getUHat()[i];
            final BigInteger rHat = s.getRHat()[i];
            tHat[i] = computeTHat(tValues[i], negC, capZ, uHat, capS, rHat, n);
        }

        // [spec: InequalityProver 2.3]
        final BigInteger capQHat = computeCapQHat(tValues, negC, s.getUHat(),
                capS, s.getAlphaHat(), n);

        // output the THat values, respecting the order as in building the
        // proof.
        for (int i = 0; i <= InequalityProver.NUM_SQUARES; i++) {
            localTHatValues.add(tHat[i]);
        }
        localTHatValues.add(capQHat);
        return localTHatValues;
    }

}
