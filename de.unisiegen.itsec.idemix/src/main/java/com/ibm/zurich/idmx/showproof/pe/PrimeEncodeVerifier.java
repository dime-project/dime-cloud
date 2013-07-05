/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.pe;

import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGAND;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGNOT;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGOR;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Class responsible for verifying that a PrimeEncode predicate holds. The
 * design is similar to RangeVerifier.
 */
public class PrimeEncodeVerifier {

    /** Proof (used to retrieve s-values/common values). */
    private final Proof proof;
    /** Prime encoding predicate to be proved. */
    private final PrimeEncodePredicate predicate;
    /** Issuer public key (used for commitments). */
    private final IssuerPublicKey ipk;
    /** Negated challenge. */
    private final BigInteger negC;

    /**
     * Contructor.
     * 
     * @param thePredicate
     *            Prime encoding predicate to be proved.
     * @param theProof
     *            Proof (used to retrieve s-values/common values).
     * @param issuerPublicKey
     *            Issuer public key (used for commitments).
     * @param theNegC
     *            Negated challenge.
     */
    public PrimeEncodeVerifier(final PrimeEncodePredicate thePredicate,
            final Proof theProof, final IssuerPublicKey issuerPublicKey,
            final BigInteger theNegC) {
        proof = theProof;
        predicate = thePredicate;
        ipk = issuerPublicKey;
        negC = theNegC;
    }

    /**
     * @return Vector containing the <tt>tHat</tt> values of the verification.
     */
    public final Vector<BigInteger> computeTHatValues() {
        switch (predicate.getOperator()) {
        case AND:
            return computeTHatValuesAND();
        case OR:
            return computeTHatValuesOR();
        case NOT:
            return computeTHatValuesNOT();
        default:
            throw new RuntimeException(
                    "Prime encoding operator not implemented.");
        }
    }

    /**
     * Implements the <tt>VerifyCGAND</tt> protocol to verify that a prime
     * encoded attribute contains the values specified by a constant.
     * 
     * @return <tt>tHat</tt> values corresponding to an AND proof.
     */
    private Vector<BigInteger> computeTHatValuesAND() {
        String idName = predicate.getIdentifier().getName();
        String name = predicate.getName();

        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();
        BigInteger n = ipk.getN();

        SValuesCGAND s = (SValuesCGAND) proof.getSValue(predicate.getName())
                .getValue();
        BigInteger capC = proof.getCommonValue(name);

        BigInteger hatM = (BigInteger) proof.getSValue(idName).getValue();
        BigInteger hatM_h = s.getMHat_h();
        BigInteger hatR = s.getRHat();
        BigInteger m_r = Utils.product(predicate.getConstants());

        // [spec: VerifyCGAND 2.] length check
        SystemParameters sp = ipk.getGroupParams().getSystemParams();
        int len = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1
                - m_r.bitLength();

        if (!Utils.isInInterval(hatM_h, len)) {
            throw new RuntimeException("Length check on EHatH in "
                    + "PrimeEncodeVerifier failed," + " bitlength is "
                    + hatM_h.bitLength() + " but should be " + len);
        }

        // [spec: VerifyCGAND 1.] compute capCHat and capCHat_0
        Vector<Exponentiation> v = new Vector<Exponentiation>();
        BigInteger base = capZ.modPow(m_r, n);
        v.add(new Exponentiation(capC, negC, n));
        v.add(new Exponentiation(base, hatM_h, n));
        v.add(new Exponentiation(capS, hatR, n));
        BigInteger capCHat = Utils.multiExpMul(v, n);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capC, negC, n));
        v.add(new Exponentiation(capZ, hatM, n));
        v.add(new Exponentiation(capS, hatR, n));
        BigInteger capCHat_0 = Utils.multiExpMul(v, n);

        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capCHat);
        localTValues.add(capCHat_0);

        return localTValues;
    }

    /**
     * Implements the <tt>VerifyCGNOT</tt> protocol to verify that a prime
     * encoded attribute contains the values specified by a constant.
     * 
     * @return <tt>tHat</tt> values corresponding to a NOT proof.
     */
    private Vector<BigInteger> computeTHatValuesNOT() {

        String name = predicate.getName();

        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();
        BigInteger n = ipk.getN();

        SValuesCGNOT s = (SValuesCGNOT) proof.getSValue(name).getValue();
        BigInteger mHat = (BigInteger) proof.getSValue(
                predicate.getIdentifier().getName()).getValue();
        BigInteger rHat = (BigInteger) proof.getSValue(name + ":rHat")
                .getValue();

        BigInteger m_r = Utils.product(predicate.getConstants());
        BigInteger base = capZ.modPow(m_r, n);
        BigInteger capC = proof.getCommonValue(name);

        BigInteger aHat = s.getAHat();
        BigInteger bHat = s.getBHat();
        BigInteger rHatPrime = s.getRHatPrime();

        // [spec: VerifyCGNOT 1.] compute t-hat-values
        Vector<Exponentiation> v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capC, aHat, n));
        v.add(new Exponentiation(capZ, negC, n));
        v.add(new Exponentiation(base, bHat, n));
        v.add(new Exponentiation(capS, rHatPrime, n));
        BigInteger capCHat = Utils.multiExpMul(v, n);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capC, negC, n));
        v.add(new Exponentiation(capZ, mHat, n));
        v.add(new Exponentiation(capS, rHat, n));
        BigInteger capCHatCommitment = Utils.multiExpMul(v, n);

        // [spec: VerifyCGNOT 2.] verify lengths
        SystemParameters sp = ipk.getGroupParams().getSystemParams();
        int n_i = predicate.getConstants().size();
        int l_t = predicate.getIdentifier().getAttStruct()
                .getL_t(ipk.getGroupParams().getSystemParams());

        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
        if (!Utils.isInInterval(mHat, bitlength)
                || !Utils.isInInterval(aHat, bitlength - n_i * l_t)
                || !Utils.isInInterval(bHat, bitlength - n_i * l_t)) {
            throw new RuntimeException("[PrimeEncodeVerifier:"
                    + "computeTHatValuesNOT()] Length check failed.");
        }

        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capCHat);
        localTValues.add(capCHatCommitment);

        return localTValues;
    }

    private Vector<BigInteger> computeTHatValuesOR() {
        String name = predicate.getName();

        BigInteger capZ = ipk.getCapZ();
        BigInteger capS = ipk.getCapS();
        BigInteger n = ipk.getN();

        SValuesCGOR s = (SValuesCGOR) proof.getSValue(name).getValue();
        BigInteger mHat = (BigInteger) proof.getSValue(
                predicate.getIdentifier().getName()).getValue();

        BigInteger m_r = Utils.product(predicate.getConstants());
        BigInteger base = capZ.modPow(m_r, n);
        BigInteger capD = proof.getCommonValue(name);
        // BigInteger capDFrak = proof.getCommonValue(name+"Frak");

        BigInteger mHat_i = s.getMHat_i();
        BigInteger alphaHat = s.getAlphaHat();
        BigInteger betaHat = s.getBetaHat();
        BigInteger rHat_0 = s.getRHat_0();
        BigInteger rHat_1 = s.getRHat_1();
        BigInteger rHat_2 = s.getRHat_2();
        // BigInteger gammaHat = s.getGammaHat();
        // BigInteger deltaHat = s.getDeltaHat();
        // BigInteger rhoHat_0 = s.getRhoHat_0();
        // BigInteger rhoHat_1 = s.getRhoHat_1();
        // BigInteger rhoHat_2 = s.getRhoHat_2();

        // [spec: VerifyCGOR 1.] compute t-hat-values
        Vector<Exponentiation> v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capD, negC, n));
        v.add(new Exponentiation(capZ, mHat_i, n));
        v.add(new Exponentiation(capS, rHat_0, n));
        BigInteger capTHat_1 = Utils.multiExpMul(v, n);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(base, negC, n));
        v.add(new Exponentiation(capD, alphaHat, n));
        v.add(new Exponentiation(capS, rHat_1, n));
        BigInteger capTHat_2 = Utils.multiExpMul(v, n);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(capD, betaHat, n));
        v.add(new Exponentiation(capZ, mHat, n));
        v.add(new Exponentiation(capS, rHat_2, n));
        BigInteger capTHat_3 = Utils.multiExpMul(v, n);

        // [spec: VerifyCGOR 2.] verify lengths
        SystemParameters sp = ipk.getGroupParams().getSystemParams();
        // int n_i = predicate.getConstants().size();
        // int l_t = predicate.getIdentifier().getAttStruct().getL_t();

        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
        if (!Utils.isInInterval(mHat_i, bitlength)
                || !Utils.isInInterval(alphaHat, bitlength)
                || !Utils.isInInterval(betaHat, bitlength)) {
            throw new RuntimeException("[PrimeEncodeVerifier:"
                    + "computeTHatValuesOR()] Length check failed.");
        }

        Vector<BigInteger> localTValues = new Vector<BigInteger>();
        localTValues.add(capTHat_1);
        localTValues.add(capTHat_2);
        localTValues.add(capTHat_3);

        return localTValues;
    }

}
