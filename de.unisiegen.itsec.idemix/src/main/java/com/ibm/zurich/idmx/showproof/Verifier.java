/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Vector;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.DomNym;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.Representation;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.ip.InequalityVerifier;
import com.ibm.zurich.idmx.showproof.pe.PrimeEncodeVerifier;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.CommitmentPredicate;
import com.ibm.zurich.idmx.showproof.predicates.DomainNymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate;
import com.ibm.zurich.idmx.showproof.predicates.MessagePredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.showproof.predicates.PseudonymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.RepresentationPredicate;
import com.ibm.zurich.idmx.showproof.predicates.VerEncPredicate;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.showproof.sval.SValuesProveCL;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;

/**
 * The Idemix show-proof verification side. This class runs the various
 * sub-proofs after getting the proof data from the prover.
 * 
 * @see Prover
 */
public class Verifier {

    /** Logger. */
    private static Logger log = Logger.getLogger(Verifier.class.getName());

    /** Group parameters. */
    private final GroupParameters gp;
    /** System parameters in use. */
    private final SystemParameters sp;

    /** nonce value. */
    private final BigInteger n1;
    /** the proof-spec we're trying to verify. */
    private final ProofSpec spec;
    /** the proof as built by the prover. */
    private final Proof proof;

    /** List of re-computed witnesses (t-Hat-values). */
    private final Vector<BigInteger> tHatList;

    /** Commitments appearing in the proof. */
    private final HashMap<String, Commitment> commitments;
    /** Representation objects to be used for this proof. */
    private final TreeMap<String, Representation> reps;
    /** Verifiable encryptions. */
    private final TreeMap<String, VerifiableEncryption> verEncs;
    /** Messages signed in the proof that we must verify. */
    private final TreeMap<String, MessageToSign> messages;

    /**
     * negative value of proof's challenge (c, Fiat-Shamir challenge) value. Is
     * used a lot, hence we keep it available as instance variable to save
     * negations.
     */
    private BigInteger negC;

    /** Computed value of Fiat-Shamir challenge. */
    private BigInteger challengeHat = null;

    /** Stores values that are revealed during the proof. */
    private HashMap<String, BigInteger> revealedValues;

    /**
     * Minimal constructor (no additional values such as commitments,
     * representations, or verifiable encryptions).
     * 
     * @param proofSpec
     *            proof-spec we're trying to verify.
     * @param theProof
     *            proof data from prover.
     * @param theN1
     *            nonce shared between prover and verifier.
     */
    public Verifier(final ProofSpec proofSpec, final Proof theProof,
            final BigInteger theN1) {
        this(proofSpec, theProof, theN1, null, null, null, null);
    }

    /**
     * Constructor.
     * 
     * @param proofSpec
     *            Proof specification we're trying to verify.
     * @param theProof
     *            Proof data from prover.
     * @param theN1
     *            Nonce shared between prover and verifier.
     * @param theMessages
     *            messages/strings that will be hashed during the proof,
     *            producing a Schnorr signature
     * @param theCommitments
     *            list of Commitments held by the verifier
     * @param theReps
     *            Representation objects the prover is proving knowledge of
     * @param theVerEncs
     *            Encryption objects the prover is proving knowledge of
     */
    public Verifier(final ProofSpec proofSpec, final Proof theProof,
            final BigInteger theN1,
            final TreeMap<String, MessageToSign> theMessages,
            final HashMap<String, Commitment> theCommitments,
            final TreeMap<String, Representation> theReps,
            final TreeMap<String, VerifiableEncryption> theVerEncs) {

        n1 = theN1;
        spec = proofSpec;

        gp = proofSpec.getGroupParams();
        sp = gp.getSystemParams();

        proof = theProof;
        commitments = theCommitments;
        reps = theReps;
        tHatList = new Vector<BigInteger>();
        verEncs = theVerEncs;
        messages = theMessages;

        revealedValues = new HashMap<String, BigInteger>();

        validate();
    }

    /**
     * Validate the proof specification.
     */
    private void validate() {
        Iterator<Predicate> predicates = spec.getPredicates().iterator();
        while (predicates.hasNext()) {
            Predicate predicate = predicates.next();
            switch (predicate.getPredicateType()) {
            case CL:
                // TODO (pbi) verify that all credential structures are
                // available
                break;
            case COMMITMENT:
                String name = ((CommitmentPredicate) predicate).getName();
                if (commitments.get(name) == null) {
                    throw new RuntimeException("Missing commitment with "
                            + "temporary name: " + name);
                }
                // TODO (pbi) verify that all commitments are used (i.e., all
                // elements in commitments are referred to by a predicate?
                break;
            case DOMAINNYM:
                break;
            case PSEUDONYM:
                break;
            case INEQUALITY:
                // TODO (pbi) verify that inequality holds?
                break;
            case VERENC:
                // TODO (pbi) verify that all verifiable encryptions are
                // available
                break;
            case REPRESENTATION:
                // TODO (pbi) verify that all required representations are
                // available
                // TODO (pbi) verify that bases in the spec == bases in the
                // object
                break;
            case MESSAGE:
                break;
            case ENUMERATION:
                break;
            default:
                throw new RuntimeException("Wrong predicate type.");
            }
        }
    }

    private static final int LOWER = 0;
    private static final int UPPER = 1;

    private static void getMHatBounds(final SystemParameters sp,
            final BigInteger bounds[]) {
        assert (bounds.length == 2);
        // compute the lower & upper bounds for length checks for mHat
        // we do this outside the loop to save a few big-int ops...
        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;

        BigInteger upper = BigInteger.ONE.shiftLeft(bitlength);
        BigInteger lower = upper.negate();
        upper = upper.subtract(BigInteger.ONE);
        lower = lower.add(BigInteger.ONE);

        bounds[LOWER] = lower;
        bounds[UPPER] = upper;
    }

    /**
     * Convenience method.
     * 
     * @param aPrime
     *            Value of <tt>A'</tt>.
     * @param n
     *            Modulus.
     * @return <tt>A'^(2^(l_e - 1)) mod n</tt>.
     */
    private BigInteger get_APrime_powered_2_le_minus_1(final BigInteger aPrime,
            final BigInteger n) {
        int expOf2 = sp.getL_e() - 1;
        final BigInteger exp = BigInteger.ONE.shiftLeft(expOf2);
        return aPrime.modPow(exp, n);
    }

    private boolean checkLength_eHat(final BigInteger eHat) {
        int bitlength = sp.getL_ePrime() + sp.getL_Phi() + sp.getL_H() + 1;
        return Utils.isInInterval(eHat, bitlength);
    }

    /**
     * The verification routine.
     * 
     * @return success or failure.
     */
    public final boolean verify() {
        // compute -c, used in sub-verifications.
        negC = proof.getChallenge().negate();

        // Iterate over predicates, calling corresponding sub-verifiers
        Iterator<Predicate> predicates = spec.getPredicates().iterator();
        while (predicates.hasNext()) {
            Predicate predicate = predicates.next();
            switch (predicate.getPredicateType()) {
            case CL:
                CLPredicate pred = (CLPredicate) predicate;
                CredentialStructure credStruct = (CredentialStructure) StructureStore
                        .getInstance().get(pred.getCredStructLocation());
                verifyCL(credStruct, pred);
                break;
            case ENUMERATION:
                tHatList.addAll(verifyPrimeEncode((PrimeEncodePredicate) predicate));
                break;
            case INEQUALITY:
                verifyInequality((InequalityPredicate) predicate);
                break;
            case COMMITMENT:
                CommitmentPredicate predComm = (CommitmentPredicate) predicate;
                Commitment comm = commitments.get(predComm.getName());
                verifyCommitment(comm, predComm);
                break;
            case REPRESENTATION:
                verifyRepresentation((RepresentationPredicate) predicate);
                break;
            case PSEUDONYM:
                verifyPseudonym((PseudonymPredicate) predicate);
                break;
            case DOMAINNYM:
                verifyDomainNym((DomainNymPredicate) predicate);
                break;
            case VERENC:
                verifyVerEnc((VerEncPredicate) predicate);
                break;
            case MESSAGE:
                verifyMessage((MessagePredicate) predicate);
                break;
            default:
                throw new RuntimeException("Unimplemented predicate.");
            }
        }

        // [spec: verifyProof 2.] Compute the challenge and compare it:
        challengeHat = computeChallengeHat();

        // [spec: verifyProof 3.]
        if (!challengeHat.equals(proof.getChallenge())) {
            log.log(Level.SEVERE, "mismatch c, cHat");
            return false;
        } else {
            log.log(Level.INFO, "c == cHat!");
        }

        return true;

    }

    /**
     * Verify the CL signature for this predicate.
     * 
     * @param credStruct
     *            Credential structure.
     * @param pred
     *            CL predicate.
     * 
     * @return success or failure.
     */
    private boolean verifyCL(final CredentialStructure credStruct,
            final CLPredicate pred) {

        final SValue clSVal = proof.getSValue(pred.getTempCredName());
        log.log(Level.FINE, pred.getTempCredName());
        assert (clSVal != null);

        final IssuerPublicKey pubKey = pred.getIssuerPublicKey();
        final BigInteger n = pubKey.getN();

        // get the blinded signature
        final BigInteger capAPrime = proof.getCommonValue(pred
                .getTempCredName());

        SValuesProveCL sValsProveCL = (SValuesProveCL) clSVal.getValue();
        final BigInteger eHat = sValsProveCL.getEHat();
        final BigInteger vHatPrime = sValsProveCL.getVHatPrime();
        // check length of eHat
        if (!checkLength_eHat(eHat)) {
            log.log(Level.SEVERE, "length check on eHat failed");
            throw new RuntimeException("[Verifier:verifyCL()] Proof of "
                    + "Knowledge of the CL signature failed.");
        }

        // Compute tHat
        Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
        Vector<Exponentiation> productNotRevealed = new Vector<Exponentiation>();

        productNotRevealed.add(new Exponentiation(capAPrime, eHat, n));

        BigInteger sMasterSecret = (BigInteger) proof.getSValue(
                IssuanceSpec.MASTER_SECRET_NAME).getValue();
        assert (sMasterSecret != null);
        productNotRevealed.add(new Exponentiation(
                pubKey.getCapR()[IssuanceSpec.MASTER_SECRET_INDEX],
                sMasterSecret, n));

        // setup the bounds for length checks on s-values
        final BigInteger[] bounds = { BigInteger.ZERO, BigInteger.ZERO };
        getMHatBounds(sp, bounds);

        // [spec: VerifyCL 1.] Iterate over the identifiers: if it's a hidden
        // value, get the s-value,
        // if it's revealed, get the value: prepare the products we need to
        // compute tHat
        Iterator<AttributeStructure> atts = credStruct.getAttributeStructs()
                .iterator();
        while (atts.hasNext()) {
            int keyIndex;
            AttributeStructure att = atts.next();
            Identifier id = pred.getIdentifier(att.getName());

            BigInteger sValue = (BigInteger) proof.getSValue(id.getName())
                    .getValue();
            keyIndex = att.getKeyIndex();
            assert (sValue != null);

            if (!id.isRevealed()) {
                // add it to the unrevealed product
                productNotRevealed.add(new Exponentiation(
                        pubKey.getCapR()[keyIndex], sValue, n));
                // [spec: VerifyCL 2.]
                if (!Utils.isInInterval(sValue, bounds[LOWER], bounds[UPPER])) {
                    throw new RuntimeException("[Verifier:verifyCL()] "
                            + "Length check failed.");
                }
            } else {
                // add revealed value to list
                revealedValues.put(pred.getTempCredName() + Constants.DELIMITER
                        + att.getName(), sValue);

                // add it to the revealed product
                productRevealed.add(new Exponentiation(
                        pubKey.getCapR()[keyIndex], sValue, n));
            }
        }

        BigInteger divisor = BigInteger.ONE;
        divisor = Utils.multiExpMul(divisor, productRevealed, n);

        divisor = divisor.multiply(
                get_APrime_powered_2_le_minus_1(capAPrime, n)).mod(n);
        // take the modular inverse of divisor
        divisor = divisor.modInverse(n);

        // initial value
        BigInteger tHat = pubKey.getCapZ();
        tHat = tHat.multiply(divisor).mod(n);
        tHat = tHat.modPow(negC, n);

        productNotRevealed.add(new Exponentiation(pubKey.getCapS(), vHatPrime,
                n));
        tHat = Utils.multiExpMul(tHat, productNotRevealed, n);

        tHatList.add(tHat);
        return true;
    }

    /**
     * @param pred
     *            Prime encode predicate.
     * @return <tt>tHat</tt> value.
     */
    private Vector<BigInteger> verifyPrimeEncode(final PrimeEncodePredicate pred) {
        IssuerPublicKey ipk = Utils.getPrimeEncodingConstants(pred);
        PrimeEncodeVerifier pev = new PrimeEncodeVerifier(pred, proof, ipk,
                negC);
        return pev.computeTHatValues();
    }

    /**
     * Verification of inequalities.
     * 
     * @param pred
     *            Inequality predicate.
     */
    private void verifyInequality(final InequalityPredicate pred) {
        if (pred.getSecondArgument() == null) {
            Identifier id = pred.getSecondArgumentIdentifier();
            id.setValue((BigInteger) proof.getSValue(id.getName()).getValue());
        }
        final InequalityVerifier rv = new InequalityVerifier(this, pred);
        final SValue sVals = proof.getSValue(pred.getName());

        SValuesIP sValuesIP;
        // adding the mHat from the CL proof!
        if (sVals.getValue() instanceof SValuesIP) {
            sValuesIP = (SValuesIP) sVals.getValue();
            sValuesIP.addMHat((BigInteger) proof.getSValue(
                    pred.getFirstArgumentIdentifier().getName()).getValue());
        } else {
            throw new RuntimeException("Wrong type of s-values. "
                    + "'SValuesIP' would be expected.");
        }
        tHatList.addAll(rv.computeTHatValues((SValuesIP) sVals.getValue()));
    }

    /**
     * Verification of commitments.
     * 
     * @param comm
     *            Commitment.
     * @param pred
     *            Commitment predicate.
     */
    private void verifyCommitment(final Commitment comm,
            final CommitmentPredicate pred) {
        assert (comm != null);

        BigInteger n = comm.getN();

        // prepare the products of revealed and hidden values in the commitment
        Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
        Vector<Exponentiation> productHidden = new Vector<Exponentiation>();

        Vector<Identifier> identifiers = pred.getIdentifiers();
        for (int i = 0; i < identifiers.size(); i++) {
            Identifier identifier = identifiers.get(i);
            BigInteger m = (BigInteger) proof.getSValue(identifier.getName())
                    .getValue();
            Exponentiation e = new Exponentiation(comm.getMsgBase(i), m, n);
            if (identifier.isRevealed()) {
                productRevealed.add(e);
            } else {
                productHidden.add(e);
            }
        }

        BigInteger cPrime = comm.getCommitment();
        if (productRevealed.size() > 0) {
            BigInteger denom = Utils.multiExpMul(productRevealed, n);
            denom = denom.modInverse(n);
            cPrime = cPrime.multiply(denom).mod(n);
        }

        productHidden.add(new Exponentiation(cPrime, negC, n));
        productHidden.add(new Exponentiation(comm.getCapS(),
                ((BigInteger) proof.getSValue(pred.getName()).getValue()), n));
        assert (productHidden != null && n != null);
        BigInteger cHat = Utils.multiExpMul(productHidden, n);

        // output cHat
        tHatList.add(cHat);
    }

    /**
     * @param pred
     *            Representation predicate.
     */
    private void verifyRepresentation(final RepresentationPredicate pred) {
        Representation rep = null;
        String name = pred.getName();

        rep = reps.get(name);
        assert (rep != null);

        // validate the bases in the proof spec vs. the representation object
        Validation.validateRepresentation(pred, rep);

        // [spec: VerifyRepresentation 1.]
        BigInteger modulus = rep.getModulus();

        // prepare the products of revealed and hidden values in the
        // Representation
        Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
        Vector<Exponentiation> productHidden = new Vector<Exponentiation>();
        for (int i = 0; i < pred.getIdentifiers().size(); i++) {
            Identifier id = pred.getIdentifier(i);
            BigInteger m;
            Exponentiation e;
            if (id.isRevealed()) {
                m = (BigInteger) proof.getSValue(id.getName()).getValue();
                e = new Exponentiation(rep.getBase(i), m, modulus);
                productRevealed.add(e);
            } else {
                m = (BigInteger) proof.getSValue(id.getName()).getValue();
                e = new Exponentiation(rep.getBase(i), m, modulus);
                productHidden.add(e);

            }
        }

        BigInteger rPrime = rep.getRepresentation();
        if (productRevealed.size() > 0) {
            BigInteger denom = Utils.multiExpMul(productRevealed, modulus);
            denom = denom.modInverse(modulus);
            rPrime = rPrime.multiply(denom).mod(modulus);
        }
        productHidden.add(new Exponentiation(rPrime, negC, modulus));

        // [spec: VerifyRepresentation 2.]
        BigInteger rHat = Utils.multiExpMul(productHidden, modulus);

        // output cHat
        tHatList.add(rHat);
    }

    /**
     * @param pred
     *            Pseudonym predicate.
     */
    private void verifyPseudonym(final PseudonymPredicate pred) {
        BigInteger nym = proof.getCommonValue(pred.getName());

        // add nym to list of revealed values
        revealedValues.put("Pseudonym" + Constants.DELIMITER + pred.getName(),
                nym);

        final BigInteger gamma = gp.getCapGamma();
        final BigInteger g = gp.getG();
        final BigInteger h = gp.getH();

        final BigInteger rHat = (BigInteger) proof.getSValue(pred.getName())
                .getValue();
        final BigInteger mHat_1 = (BigInteger) proof.getSValue(
                IssuanceSpec.MASTER_SECRET_NAME).getValue();

        final Vector<Exponentiation> e = new Vector<Exponentiation>();
        e.add(new Exponentiation(nym, negC, gamma));
        e.add(new Exponentiation(g, mHat_1, gamma));
        e.add(new Exponentiation(h, rHat, gamma));

        final BigInteger nymHat = Utils.multiExpMul(e, gamma);

        tHatList.add(nymHat);
    }

    /**
     * Verification of domain nym.
     * 
     * @param pred
     *            Domain pseudonym predicate.
     */
    private void verifyDomainNym(final DomainNymPredicate pred) {
        BigInteger proverDomNym = proof.getCommonValue(pred.getDomain());
        DomNym domNym = new DomNym(gp, proverDomNym, pred.getDomain());

        // add domNym to list of revealed values
        revealedValues.put(
                "DomainPseudonym" + Constants.DELIMITER + pred.getDomain(),
                proverDomNym);

        BigInteger mHat_1 = (BigInteger) proof.getSValue(
                IssuanceSpec.MASTER_SECRET_NAME).getValue();
        assert (mHat_1 != null);

        final BigInteger gamma = gp.getCapGamma();

        Vector<Exponentiation> product = new Vector<Exponentiation>();
        product.add(new Exponentiation(domNym.getNym(), negC, gamma));
        product.add(new Exponentiation(domNym.getG_dom(), mHat_1, gamma));

        BigInteger dNymHat = Utils.multiExpMul(product, gamma);
        tHatList.add(dNymHat);
    }

    /**
     * @param pred
     *            Verifiable encryption predicate.
     */
    private void verifyVerEnc(final VerEncPredicate pred) {
        // get the s-values
        BigInteger mHat = null;
        mHat = (BigInteger) proof.getSValue(pred.getIdentifier().getName())
                .getValue();

        assert (mHat != null);

        SValue sv = proof.getSValue(pred.getName());
        assert (sv != null);
        BigInteger rHat = (BigInteger) sv.getValue();

        // find the right Encryption object
        VerifiableEncryption ve = null;
        ve = proof.getVerEnc(pred.getName());
        if (ve == null) {
            ve = verEncs.get(pred.getName());
        }
        assert (ve != null);

        VEPublicKey pk = pred.getPublicKey();
        BigInteger n2 = pk.getN2();
        BigInteger twoNegC = negC.multiply(Utils.TWO);
        BigInteger twoRHat = rHat.multiply(Utils.TWO);
        BigInteger twoMHat = mHat.multiply(Utils.TWO);

        Vector<Exponentiation> v = new Vector<Exponentiation>();
        v.add(new Exponentiation(ve.getU(), twoNegC, n2));
        v.add(new Exponentiation(pk.getG(), twoRHat, n2));
        BigInteger uHat = Utils.multiExpMul(v, n2);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(ve.getE(), twoNegC, n2));
        v.add(new Exponentiation(pk.getY1(), twoRHat, n2));
        v.add(new Exponentiation(pk.getH(), twoMHat, n2));
        BigInteger eHat = Utils.multiExpMul(v, n2);

        v = new Vector<Exponentiation>();
        v.add(new Exponentiation(ve.getV(), twoNegC, n2));
        v.add(new Exponentiation(pk.getY2(), twoRHat, n2));
        v.add(new Exponentiation(pk.getY3(), twoRHat.multiply(ve.getHash()), n2));
        BigInteger vHat = Utils.multiExpMul(v, n2);

        log.log(Level.FINE, " uHat: " + Utils.logBigInt(uHat));
        log.log(Level.FINE, " eHat: " + Utils.logBigInt(eHat));
        log.log(Level.FINE, " vHat: " + Utils.logBigInt(vHat));

        tHatList.add(uHat);
        tHatList.add(eHat);
        tHatList.add(vHat);
    }

    /**
     * @param pred
     *            Message predicate.
     */
    private void verifyMessage(final MessagePredicate pred) {
        assert (messages != null);
        assert (!messages.isEmpty());
        MessageToSign msg = messages.get(pred.getName());
        assert (msg != null);

        Validation.validateMessage(pred, msg);
    }

    /**
     * @return FS challenge value.
     */
    private BigInteger computeChallengeHat() {
        Vector<BigInteger> list = new Vector<BigInteger>();
        // TODO (pbi) define how the common list and messages should be ordered
        // (cf. Prover.java)
        list.addAll(proof.getCommonList().values());
        list.addAll(tHatList);

        BigInteger challenge = null;
        if (messages != null) {
            challenge = Utils.computeChallenge(sp, spec.getContext(), list, n1,
                    messages.values());
        } else {
            challenge = Utils.computeChallenge(sp, spec.getContext(), list, n1,
                    null);
        }
        return challenge;
    }

    /**
     * To retrieve the common value for a range proof predicate.
     * 
     * @param tag
     *            range proof tag.
     * @return common value or null.
     */
    public BigInteger getCommonValRP(final String tag) {
        return proof.getCommonValue(tag);
    }

    public BigInteger getNegC() {
        return negC;
    }

    public final HashMap<String, BigInteger> getRevealedValues() {
        return revealedValues;
    }

    /**
     * @param sp
     *            System parameters.
     * @return Verifier's nonce.
     */
    public static BigInteger getNonce(final SystemParameters sp) {
        return Utils.computeRandomNumberSymmetric(sp.getL_m());
    }
}
