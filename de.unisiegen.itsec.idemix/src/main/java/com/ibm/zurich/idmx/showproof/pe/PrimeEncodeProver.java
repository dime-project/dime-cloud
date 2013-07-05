/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.pe;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGAND;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGNOT;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGOR;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Class responsible for proving that a PrimeEncode predicate holds. The design
 * is similar to RangeProver.
 */
public class PrimeEncodeProver {

    /**
     * Link to the caller so that we may access the t-values and the common
     * values.
     */
    private final Prover prover;
    /** Prime encoding predicate to be proved. */
    private final PrimeEncodePredicate predicate;
    /** Issuer public key (used for commitments). */
    private final IssuerPublicKey ipk;
    /** Values from the first round that are needed to compute the s-values. */
    private Hashtable<String, BigInteger> state;

    /**
     * Constructor.
     * 
     * @param pred
     *            Prime encoding predicate to be proved.
     * @param theProver
     *            Link to the caller.
     * @param issuerPublicKey
     *            Issuer public key (used for commitments).
     */
    public PrimeEncodeProver(final PrimeEncodePredicate pred,
            final Prover theProver, final IssuerPublicKey issuerPublicKey) {
        prover = theProver;
        predicate = pred;
        ipk = issuerPublicKey;
        state = new Hashtable<String, BigInteger>();
    }

    /**
     * @return T-values using the appropriate (depending on the operator)
     *         sub-routine.
     */
    public final Vector<BigInteger> computeTValues() {
        switch (predicate.getOperator()) {
        case AND:
            return computeTValuesAND();
        case OR:
            return computeTValuesOR();
        case NOT:
            return computeTValuesNOT();
        default:
            throw new RuntimeException(
                    "Prime encoding operator not implemented.");
        }
    }

    /**
     * Computes the s-values using the appropriate (depending on the operator)
     * sub-routine.
     * 
     * @param challenge
     *            Challenge.
     * @return Map of s-values.
     */
    public final HashMap<String, SValue> computeSValues(
            final BigInteger challenge) {
        switch (predicate.getOperator()) {
        case AND:
            return computeSValuesAND(challenge);
        case OR:
            return computeSValuesOR(challenge);
        case NOT:
            return computeSValuesNOT(challenge);
        default:
            throw new RuntimeException(
                    "Prime encoding operator not implemented.");
        }
    }

    /**
     * @return Commitment and t-value for the AND predicate (appended to
     *         prover's t-value and common value lists), and store the
     *         randomness in order to compute the s-values.
     */
    private Vector<BigInteger> computeTValuesAND() {
        String name = predicate.getName();

        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();
        BigInteger n = ipk.getN();

        SystemParameters sp = ipk.getGroupParams().getSystemParams();

        // create the commitment
        Vector<BigInteger> constants = predicate.getConstants();
        int n_i = constants.size();
        int l_t = predicate.getIdentifier().getAttStruct()
                .getL_t(ipk.getGroupParams().getSystemParams());
        BigInteger m_r = Utils.product(constants);
        BigInteger m = predicate.getIdentifier().getValue();

        // make sure m_r divides m
        if (!(m.mod(m_r)).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Cannot prove "
                    + predicate.toStringPretty()
                    + " reavealed portion of prime encoded atttribute"
                    + " does not divide the attribute (." + m + ")");
        }
        BigInteger m_h = m.divide(m_r);

        // [spec: ProveCGAND 1.]
        BigInteger r = CommitmentOpening.genRandom(n, ipk.getGroupParams()
                .getSystemParams().getL_n());
        CommitmentOpening capC = new CommitmentOpening(capZ, m, capS, r, n,
                sp.getL_n());

        // [spec: ProveCGAND 2.] create the t-values
        BigInteger mTilde_h = getTildeRandom(sp, n_i * l_t);
        BigInteger rTilde = getTildeRandom(sp);

        Vector<Exponentiation> v = new Vector<Exponentiation>();
        BigInteger base = capZ.modPow(m_r, n);
        v.add(new Exponentiation(base, mTilde_h, n));
        v.add(new Exponentiation(capS, rTilde, n));
        BigInteger capCTilde = Utils.multiExpMul(v, n);

        BigInteger mTilde = predicate.getIdentifier().getRandom();
        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capZ, mTilde, n));
        v.add(new Exponentiation(capS, rTilde, n));
        BigInteger capCTilde_0 = Utils.multiExpMul(v, n);

        // store in the state for the second part of the proof
        state.put("rTilde", rTilde);
        state.put("mTilde_h", mTilde_h);
        state.put("m_h", m_h);
        state.put("r", r);

        // output t-value tildeC, common value c
        prover.appendCommonValue(name, capC.getCommitment());

        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capCTilde);
        localTValues.add(capCTilde_0);

        return localTValues;
    }

    /**
     * Given the challenge, computes the s-values from the stored random values,
     * and adds them to the prover's global list.
     * 
     * @param challenge
     *            Challenge.
     * @return Map of s-values.
     */
    private HashMap<String, SValue> computeSValuesAND(final BigInteger challenge) {
        String name = predicate.getName();

        BigInteger rTilde = state.get("rTilde");
        BigInteger mTilde_h = state.get("mTilde_h");
        BigInteger m_h = state.get("m_h");
        BigInteger r = state.get("r");

        BigInteger mHat_h = Utils.computeResponse(mTilde_h, challenge, m_h);
        BigInteger hatR = Utils.computeResponse(rTilde, challenge, r);
        SValue s = new SValue(new SValuesCGAND(mHat_h, hatR));

        HashMap<String, SValue> localSValues = new HashMap<String, SValue>();
        localSValues.put(name, s);
        return localSValues;
    }

    /**
     * @return Commitment and the t-values for a NOT proof of a prime encoded
     *         attribute.
     */
    private Vector<BigInteger> computeTValuesNOT() {
        String name = predicate.getName();

        SystemParameters sp = ipk.getGroupParams().getSystemParams();

        BigInteger n = ipk.getN();
        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();

        Vector<BigInteger> constants = predicate.getConstants();
        int n_i = constants.size();
        int l_t = predicate.getIdentifier().getAttStruct()
                .getL_t(ipk.getGroupParams().getSystemParams());
        BigInteger m_r = Utils.product(constants);
        BigInteger m = predicate.getIdentifier().getValue();

        BigInteger r;
        CommitmentOpening capC;

        // [spec: ProveCGNOT 1.]
        // TODO (pbi) no commitment is needed if the value there is already one
        // if (predicate.getIdentifier().isUnrevealed()) {
        //
        // assert (((COAttr) attributeCapE_i).getCommitment() instanceof
        // CommitmentOpening);
        // capC = (CommitmentOpening) ((COAttr) attributeCapE_i)
        // .getCommitment();
        // r = capC.getRandom();
        //
        // System.out.println("capZ: "+ capZ);
        // System.out.println("capZ: "+ capC.getMsgBase(0));
        //
        // } else {

        // [spec: ProveCGNOT 1.1]
        r = CommitmentOpening.genRandom(n, sp.getL_n());
        // [spec: ProveCGNOT 1.2]
        capC = new CommitmentOpening(capZ, m, capS, r, n, sp.getL_n());

        // }

        // make sure m_r does not divide m
        if ((m.mod(m_r)).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Cannot prove "
                    + predicate.toStringPretty() + " as the reavealed "
                    + "portion of prime encoded attribute does divide "
                    + "the attribute (" + m + ")");
        }

        // [spec: ProveCGNOT 1.3]
        BigInteger rTilde = getTildeRandom(sp);
        BigInteger mTilde = predicate.getIdentifier().getRandom();
        // [spec: ProveCGNOT 1.4]
        BigInteger[] euclid = Utils.extendedEuclid(m, m_r);
        BigInteger a = euclid[0];
        BigInteger b = euclid[1];
        // [spec: ProveCGNOT 1.5]
        BigInteger rPrime = capC.getRandom().multiply(a).negate();

        // [spec: ProveCGNOT 2.1] create the t-values
        BigInteger aTilde = getTildeRandom(sp, n_i * l_t);
        BigInteger bTilde = getTildeRandom(sp, n_i * l_t);
        BigInteger rTildePrime = getTildeRandom(sp, n_i * l_t);
        // [spec: ProveCGNOT 2.2]
        Vector<Exponentiation> v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capC.getCommitment(), aTilde, n));
        v.add(new Exponentiation(capZ, bTilde.multiply(m_r), n));
        v.add(new Exponentiation(capS, rTildePrime, n));
        BigInteger capCTilde = Utils.multiExpMul(v, n);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capZ, mTilde, n));
        v.add(new Exponentiation(capS, rTilde, n));
        BigInteger capCTildeCommitment = Utils.multiExpMul(v, n);

        // store in the state for the second part of the proof
        state.put("a", a);
        state.put("b", b);
        state.put("rPrime", rPrime);
        state.put("aTilde", aTilde);
        state.put("bTilde", bTilde);
        state.put("rTildePrime", rTildePrime);
        state.put("r", r);
        state.put("rTilde", rTilde);

        // [spec: ProveCGNOT 3.] output t-value tildeC, common value c
        prover.appendCommonValue(name, capC.getCommitment());
        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capCTilde);
        localTValues.add(capCTildeCommitment);

        return localTValues;
    }

    /**
     * Computes the s-values from the stored random values using the given
     * challenge and adds the s-values to the prover's global list.
     * 
     * @param challenge
     *            Challenge.
     * @return Map of s-values.
     */
    private HashMap<String, SValue> computeSValuesNOT(final BigInteger challenge) {
        BigInteger a = state.get("a");
        BigInteger b = state.get("b");
        BigInteger rPrime = state.get("rPrime");
        BigInteger aTilde = state.get("aTilde");
        BigInteger bTilde = state.get("bTilde");
        BigInteger rTildePrime = state.get("rTildePrime");
        BigInteger r = state.get("r");
        BigInteger rTilde = state.get("rTilde");

        // [spec: ProveCGNOT 4.] compute s-values
        BigInteger aHat = Utils.computeResponse(aTilde, challenge, a);
        BigInteger bHat = Utils.computeResponse(bTilde, challenge, b);
        BigInteger rHatPrime = Utils.computeResponse(rTildePrime, challenge,
                rPrime);
        BigInteger rHat = Utils.computeResponse(rTilde, challenge, r);

        SValue s = new SValue(new SValuesCGNOT(aHat, bHat, rHatPrime));
        SValue s_r = new SValue(rHat);

        HashMap<String, SValue> localSValues = new HashMap<String, SValue>();
        localSValues.put(predicate.getName(), s);
        localSValues.put(predicate.getName() + ":rHat", s_r);
        return localSValues;
    }

    private CommitmentOpening capD;

    /**
     * @return Commitments and the t-values for an OR proof of a prime encoded
     *         attribute.
     */
    private Vector<BigInteger> computeTValuesOR() {
        String name = predicate.getName();

        SystemParameters sp = ipk.getGroupParams().getSystemParams();

        BigInteger n = ipk.getN();
        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();

        Vector<BigInteger> constants = predicate.getConstants();
        // int n_i = constants.size();
        // int l_t = predicate.getIdentifier().getAttStruct().getL_t();
        // BigInteger m_r = Utils.product(constants);
        BigInteger m = predicate.getIdentifier().getValue();
        BigInteger m_i = null;

        for (int i = 0; i < constants.size(); i++) {
            if (m.mod(constants.get(i)).equals(BigInteger.ZERO)) {
                m_i = constants.get(i);
                break;
            }
        }

        if (m_i == null) {
            throw new RuntimeException("[PrimeEncodeProver:computeTValuesOR] "
                    + "Predicate does not hold.");
        }

        // [spec: ProveCGOR 1.] (note, that we need most of the values only for
        // calculation of the s-values, thus, they are not computed now)
        BigInteger r_0 = CommitmentOpening.genRandom(n, sp.getL_n());
        // BigInteger gamma = m_i.subtract(BigInteger.ONE).modInverse(q);
        // BigInteger delta = m_i.add(BigInteger.ONE).modInverse(q);
        // BigInteger rho_0 = select from Z_q;
        // BigInteger rho_1 = rho_0.multiply(gamma).negate();
        // BigInteger rho_2 = rho_0.multiply(delta).negate();

        // [spec: ProveCGOR 2.]
        capD = new CommitmentOpening(capZ, m_i, capS, r_0, n, sp.getL_n());
        // CommitmentOpening capDFrak = new CommitmentOpening(gFrak, m_i, hFrak,
        // rho_0, n, sp.getL_n());

        // [spec: ProveCGOR 3.1]
        BigInteger mTilde_i = getTildeRandom(sp, 0);
        BigInteger rTilde_0 = getTildeRandom(sp);
        BigInteger alphaTilde = getTildeRandom(sp, 0);
        BigInteger rTilde_1 = getTildeRandom(sp);
        BigInteger betaTilde = getTildeRandom(sp, 0);
        BigInteger mTilde = predicate.getIdentifier().getRandom();
        BigInteger rTilde_2 = getTildeRandom(sp);
        // BigInteger rhoTilde_0 = getTildeRandom(sp);
        // BigInteger gammaTilde = getTildeRandom(sp, 0);
        // BigInteger rhoTilde_1 = getTildeRandom(sp);
        // BigInteger deltaTilde = getTildeRandom(sp, 0);
        // BigInteger rhoTilde_2 = getTildeRandom(sp);

        // [spec: ProveCGOR 3.2]
        Vector<Exponentiation> e = new Vector<Exponentiation>();
        e.add(new Exponentiation(capZ, mTilde_i, n));
        e.add(new Exponentiation(capS, rTilde_0, n));
        BigInteger capTTilde_1 = Utils.multiExpMul(e, n);

        e = new Vector<Exponentiation>();
        e.add(new Exponentiation(capD.getCommitment(), alphaTilde, n));
        e.add(new Exponentiation(capS, rTilde_1, n));
        BigInteger capTTilde_2 = Utils.multiExpMul(e, n);

        e = new Vector<Exponentiation>();
        e.add(new Exponentiation(capD.getCommitment(), betaTilde, n));
        e.add(new Exponentiation(capZ, mTilde, n));
        e.add(new Exponentiation(capS, rTilde_2, n));
        BigInteger capTTilde_3 = Utils.multiExpMul(e, n);

        // e = new Vector<Exponentiation>();
        // e.add(new Exponentiation(gFrak, mTilde_i, n));
        // e.add(new Exponentiation(hFrak, rhoTilde_0, n));
        // BigInteger capTTilde_4 = Utils.multiExpMul(e, n);
        //
        // e = new Vector<Exponentiation>();
        // BigInteger gFrakInverse = gFrak.modInverse(n);
        // e.add(new
        // Exponentiation(capDFrak.getCommitment().multiply(gFrakInverse),
        // gammaTilde, n));
        // e.add(new Exponentiation(hFrak, rhoTilde_1, n));
        // BigInteger capTTilde_5 = Utils.multiExpMul(e, n);
        //
        // e = new Vector<Exponentiation>();
        // e.add(new Exponentiation(capDFrak.getCommitment().multiply(gFrak),
        // deltaTilde, n));
        // e.add(new Exponentiation(hFrak, rhoTilde_2, n));
        // BigInteger capTTilde_6 = Utils.multiExpMul(e, n);

        // store in the state for the second part of the proof
        state.put("m_i", m_i);
        state.put("r_0", r_0);
        state.put("mTilde_i", mTilde_i);
        state.put("rTilde_0", rTilde_0);
        state.put("alphaTilde", alphaTilde);
        state.put("rTilde_1", rTilde_1);
        state.put("betaTilde", betaTilde);
        state.put("mTilde", mTilde);
        state.put("rTilde_2", rTilde_2);

        // [spec: ProveCGOR 4.] output t-values and common values
        prover.appendCommonValue(name, capD.getCommitment());
        // prover.appendCommonValue(name+"Frak", capDFrak.getCommitment());

        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capTTilde_1);
        localTValues.add(capTTilde_2);
        localTValues.add(capTTilde_3);

        System.out.println("capTTilde_1: \t" + Utils.logBigInt(capTTilde_1));
        System.out.println("capTTilde_2: \t" + Utils.logBigInt(capTTilde_2));
        System.out.println("capTTilde_3: \t" + Utils.logBigInt(capTTilde_3));

        return localTValues;
    }

    /**
     * @param challenge
     *            Challenge.
     * @return Map of s-values.
     */
    private HashMap<String, SValue> computeSValuesOR(final BigInteger challenge) {
        BigInteger m_r = Utils.product(predicate.getConstants());
        BigInteger m = predicate.getIdentifier().getValue();

        BigInteger m_i = state.get("m_i");
        BigInteger r_0 = state.get("r_0");
        BigInteger mTilde_i = state.get("mTilde_i");
        BigInteger rTilde_0 = state.get("rTilde_0");
        BigInteger alphaTilde = state.get("alphaTilde");
        BigInteger rTilde_1 = state.get("rTilde_1");
        BigInteger betaTilde = state.get("betaTilde");
        BigInteger rTilde_2 = state.get("rTilde_2");

        // [spec: ProveCGOR 1.] (remaining values)
        BigInteger alpha = m_r.divide(m_i);
        BigInteger beta = m.divide(m_i).negate();
        BigInteger r_1 = r_0.multiply(alpha).negate();
        BigInteger r_2 = r_0.multiply(beta).negate();

        BigInteger mHat_i = Utils.computeResponse(mTilde_i, challenge, m_i);
        BigInteger alphaHat = Utils.computeResponse(alphaTilde, challenge,
                alpha);
        BigInteger betaHat = Utils.computeResponse(betaTilde, challenge, beta);
        BigInteger rHat_0 = Utils.computeResponse(rTilde_0, challenge, r_0);
        BigInteger rHat_1 = Utils.computeResponse(rTilde_1, challenge, r_1);
        BigInteger rHat_2 = Utils.computeResponse(rTilde_2, challenge, r_2);

        SValue s = new SValue(new SValuesCGOR(mHat_i, alphaHat, betaHat,
                rHat_0, rHat_1, rHat_2));

        HashMap<String, SValue> localSValues = new HashMap<String, SValue>();
        localSValues.put(predicate.getName(), s);

        return localSValues;
    }

    /**
     * Returns a random value (e.g., for an integer commitment), of length
     * <tt>l_n + l_phi + l_H + 1</tt>.
     * 
     * @param sp
     *            System parameters.
     * @return random value.
     */
    private static BigInteger getTildeRandom(final SystemParameters sp) {
        int bitlength = sp.getL_n() + sp.getL_Phi() + sp.getL_H() + 1;
        return Utils.computeRandomNumberSymmetric(bitlength);
    }

    /**
     * Returns a symmetric random value for an integer commitment, of bit length
     * <tt>l_m + l_phi +l_H + 1 - x</tt>.
     * 
     * @param sp
     *            System parameters.
     * @param x
     *            Bit length that is subtracted.
     * @return random value.
     */
    private static BigInteger getTildeRandom(final SystemParameters sp,
            final int x) {
        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1 - x;
        return Utils.computeRandomNumberSymmetric(bitlength);
    }

}
