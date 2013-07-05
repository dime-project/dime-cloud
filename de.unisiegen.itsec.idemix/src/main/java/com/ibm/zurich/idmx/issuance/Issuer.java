/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.issuance;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.DomNym;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zurich.idmx.issuance.update.UpdateSpecification;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Class implementing the Issuer, an authority who can issue credentials and
 * update them.
 * 
 * @see Recipient
 */
public class Issuer {

    /** Logger. */
    private static Logger log = Logger.getLogger(Issuer.class.getName());

    /** Key pair of the issuer. */
    private final IssuerKeyPair issuerKeyPair;
    /** Specification of the issuing process. */
    private final IssuanceSpec spec;
    /** Credential structure used for the issuing process. */
    private final CredentialStructure certStruct;
    /** Values for the issuance process (i.e., known attribute values). */
    private final Values values;

    /** Pseudonym. */
    private final BigInteger nym;
    /** Domain pseudonym. */
    private final DomNym domNym;
    /** Nonce. */
    private BigInteger nonce1;

    /** Convenience: System parameters. */
    private final SystemParameters sp;
    /** Convenience: Group parameters. */
    private final GroupParameters gp;
    /** Data that allows to update a credential. */
    private IssuerUpdateInformation issuerUpdateInformation;

    /**
     * Convenience constructor.
     */
    public Issuer(final IssuerKeyPair issuerKey,
            final IssuanceSpec issuanceSpec, final Values theValues) {
        this(issuerKey, issuanceSpec, null, null, theValues);
    }

    /**
     * Create an Issuer, to issue a credential to a Recipient.
     * 
     * @param issuerKey
     *            The issuer's public and private key.
     * @param issuanceSpec
     *            Issuance specification, describing what will be in the
     *            credential and how it will be issued.
     * @param pseudonym
     *            Pseudonym (optional).
     * @param theDomNym
     *            Domain pseudonym (optional).
     * @param theValues
     *            Values known to the issuer.
     */
    public Issuer(final IssuerKeyPair issuerKey,
            final IssuanceSpec issuanceSpec, final BigInteger pseudonym,
            final DomNym theDomNym, final Values theValues) {
        super();

        gp = issuerKey.getPublicKey().getGroupParams();
        sp = gp.getSystemParams();

        issuerKeyPair = issuerKey;
        spec = issuanceSpec;
        nym = pseudonym;
        domNym = theDomNym;

        certStruct = spec.getCredentialStructure();
        values = theValues;

        if (!certStruct.verifyIssuerValues(values)) {
            throw new IllegalArgumentException("Values given to the "
                    + "issuer do not correspond to the credential "
                    + "structure.");
        }
    }

    /**
     * @return Random nonce n1.
     */
    public final BigInteger getNonce1() {
        // choose a random nonce n1 \in {0,1}^l_Phi.
        nonce1 = Utils.computeRandomNumber(sp.getL_Phi());
        return nonce1;
    }

    /**
     * @param negChallenge
     *            Negated challenge <tt>-c</tt>.
     * @param sValues
     *            <tt>mHat</tt> and <tt>rHat</tt> values.
     * @return T-value <tt>CHat</tt>.
     */
    private HashMap<String, BigInteger> getCHat(final BigInteger negChallenge,
            final HashMap<String, SValue> sValues) {
        Vector<AttributeStructure> attStructs = certStruct
                .getAttributeStructs(IssuanceMode.COMMITTED);
        HashMap<String, BigInteger> v = new HashMap<String, BigInteger>();

        for (AttributeStructure attStruct : attStructs) {
            final String theName = attStruct.getName();

            Commitment commitment = ((Commitment) values.get(
                    attStruct.getName()).getContent());
            final BigInteger comm = commitment.getCommitment();
            final BigInteger modulus = commitment.getN();

            BigInteger bi = BigInteger.ONE;

            Vector<Exponentiation> expos = new Vector<Exponentiation>();
            // c_j^{-c} (mod n)
            expos.add(new Exponentiation(comm, negChallenge, modulus));
            // Z_{j}^{mHat_j} (mod n)
            expos.add(new Exponentiation(commitment.getCapR(),
                    (BigInteger) sValues.get(theName).getValue(), modulus));
            // S_{j}^{rHat_j} (mod n)
            expos.add(new Exponentiation(commitment.getCapS(),
                    (BigInteger) sValues.get(
                            theName + Constants.DELIMITER + "rHat").getValue(),
                    modulus));
            bi = Utils.multiExpMul(expos, modulus);
            v.put(theName, bi);

        }
        return v;
    }

    /**
     * Checks if all values are within the required interval.
     * 
     * @param theValues
     *            Values to be checked (i.e., the s-values and the random values
     *            for the additional commitments <tt>rHat</tt>).
     */
    private void checkInterval(final HashMap<String, SValue> theValues) {
        int bitlength;

        Iterator<String> iterator = theValues.keySet().iterator();

        while (iterator.hasNext()) {
            String name = iterator.next();
            if (name.endsWith("rHat")) {
                bitlength = sp.getL_n() + 2 * sp.getL_Phi() + sp.getL_H();
            } else {
                bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
            }
            final BigInteger upperBound = BigInteger.ONE.shiftLeft(bitlength);
            final BigInteger lowerBound = upperBound.negate();

            if (!Utils.isInInterval(
                    (BigInteger) theValues.get(name).getValue(), lowerBound,
                    upperBound)) {
                throw new RuntimeException("elem ["
                        + Utils.logBigInt((BigInteger) theValues.get(name)
                                .getValue()) + "] with name " + name + " is "
                        + "outside interval with bit length: " + bitlength
                        + ".");
            }
        }
    }

    /**
     * To correctly initiate the Issuer it requires to create a nonce. This
     * nonce guarantees the freshness of the proof created by the Recipient.
     * 
     * @return a response to the Recipient containing the nonce.
     */
    public final Message round0() {
        HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
        issuanceProtocolValues = new HashMap<Message.IssuanceProtocolValues, BigInteger>();
        issuanceProtocolValues.put(IssuanceProtocolValues.nonce,
                getNonce1());
        return new Message(issuanceProtocolValues, null, null);
    }

    /**
     * Convenience method. Stores the nonce generated by the issuer and
     * redirects to round2(Message). Note that the Issuer <b>MUST</b> be sure
     * that the nonce is related to the nonce generated by himself as otherwise
     * the security properties cannot be guaranteed!
     * 
     * @see Issuer#round2(Message).
     */
    public final Message round2(final BigInteger nonce, final Message msg) {
        nonce1 = nonce;
        return round2(msg);
    }

    /**
     * The main functionality of the Issuer. Once initialized, the Issuer
     * receives a message from the Recipient, and computes a response,
     * consisting of the CL signature, and proof that it was correctly computed.
     * 
     * @param msg
     *            the first flow of the protocol; a message from the Recipient.
     * @return a response to the Recipient.
     */
    public final Message round2(final Message msg) {

        final BigInteger c = msg.getProof().getChallenge();
        HashMap<String, SValue> sValues = (HashMap<String, SValue>) msg
                .getProof().getSValues();

        Vector<AttributeStructure> attStructs = certStruct
                .getAttributeStructs();

        // m1Hat: master secret mHat value.
        final BigInteger mHat_1 = (BigInteger) sValues.get(
                IssuanceSpec.MASTER_SECRET_NAME).getValue();

        final BigInteger vHatPrime = msg.getProof().getCommonValue(
                IssuanceSpec.vHatPrime);

        final BigInteger negC = c.negate();
        final BigInteger capGamma = gp.getCapGamma();

        BigInteger nymHat = null;
        BigInteger domNymHat = null;
        if (nym != null) {
            nymHat = Utils.computeCommitment(gp, mHat_1, msg.getProof()
                    .getCommonValue(IssuanceSpec.rHat));
            nymHat = Utils.expMul(nymHat, nym, negC, capGamma);
        }
        if (domNym != null) {
            domNymHat = Utils
                    .expMul(domNymHat, domNym.getNym(), negC, capGamma);
            domNymHat = Utils.expMul(domNymHat, domNym.getG_dom(), mHat_1,
                    capGamma);
        }

        final BigInteger n = issuerKeyPair.getPublicKey().getN();

        BigInteger capUHat;
        final BigInteger[] capR = issuerKeyPair.getPublicKey().getCapR();
        final BigInteger capU = msg
                .getIssuanceElement(IssuanceProtocolValues.capU);

        final Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(capU, negC, n));
        expos.add(new Exponentiation(issuerKeyPair.getPublicKey().getCapS(),
                msg.getProof().getCommonValue(IssuanceSpec.vHatPrime), n));
        expos.addAll(addHatAttExpos(attStructs, sValues, capR, n));

        capUHat = Utils.multiExpMul(expos, n);
        capUHat = capUHat
                .multiply(
                        capR[IssuanceSpec.MASTER_SECRET_INDEX].modPow(
                                (BigInteger) sValues.get(
                                        IssuanceSpec.MASTER_SECRET_NAME)
                                        .getValue(), n)).mod(n);

        final HashMap<String, BigInteger> capCHat = getCHat(negC, sValues);

        BigInteger domNymNym = null;
        if (domNym != null) {
            domNymNym = domNym.getNym();
        }

        final BigInteger cHat = Utils.computeFSChallenge(sp, spec.getContext(),
                capU, attStructs, values, nym, domNymNym, capUHat, capCHat,
                nymHat, domNymHat, nonce1);

        if (!cHat.equals(c)) {
            log.log(Level.SEVERE, "mismatching c, cHat (" + c.toString() + ", "
                    + cHat.toString() + ")");
            return null;
        }

        // check that vHatPrime has right bit length.
        int bitlength = sp.getL_n() + 2 * sp.getL_Phi() + sp.getL_H() + 1;
        if (!Utils.isInInterval(vHatPrime, bitlength)) {
            log.log(Level.SEVERE, "vHatPrime fails range check.");
            return null;
        }
        // check that mHat and rHat are in correct interval.
        checkInterval(sValues);
        // we can now start generating the signature.
        final BigInteger e = Utils.chooseE(sp);

        /**
         * offset = 2^(l_e-1), e in [2^(l_e - 1).. 2^(l_e -1) + 2^(lPrime_e - 1)
         * means we can pick the randomness in the interval [0..2^(lPrime_e -
         * 1)] and then add the offset.
         * */
        /*
         * final BigInteger offset = BigInteger.ONE.shiftLeft( sp.getL_e() - 1);
         * do { e = Utils.computeRandomNumber( sp.getL_prime_e() - 1); // add
         * offset e = e.add(offset); } while ( !e.isProbablePrime(
         * sp.getL_pt()));
         */

        final BigInteger vTilde = Utils.computeRandomNumber(sp.getL_v() - 1);
        final BigInteger vPrimePrime = vTilde.add(BigInteger.ONE.shiftLeft(sp
                .getL_v() - 1));

        final IssuerPrivateKey privKey = issuerKeyPair.getPrivateKey();
        // p = 2*p' + 1, q = 2*q' + 1
        final BigInteger pPrime_qPrime = privKey.computeQPrimePPrime();
        // getPPrime().multiply( privKey.getQPrime());
        final BigInteger eInverse = e.modInverse(pPrime_qPrime);

        final IssuerPublicKey pubKey = issuerKeyPair.getPublicKey();
        final BigInteger capQ = computeQ(pubKey.getCapS(), capU,
                pubKey.getCapZ(), pubKey.getCapR(), vPrimePrime, pubKey.getN(),
                certStruct.getAttributeStructs(IssuanceMode.KNOWN), values);
        log.log(Level.FINE, "capQ: " + Utils.logBigInt(capQ));

        final BigInteger capA = capQ.modPow(eInverse, n);

        // [spec: IssueCredentialProtocol 2.2]
        BigInteger context = spec.getContext();
        BigInteger nonce_recipient = msg
                .getIssuanceElement(IssuanceProtocolValues.nonce);
        Vector<BigInteger> proofContext = new Vector<BigInteger>();
        proofContext.add(context);
        proofContext.add(capQ);
        proofContext.add(capA);
        proofContext.add(nonce_recipient);

        final Proof p2 = computeATildeProof(proofContext, sp, n, pPrime_qPrime,
                eInverse, capQ);

        Message response;
        HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
        issuanceProtocolValues = new HashMap<Message.IssuanceProtocolValues, BigInteger>();
        issuanceProtocolValues.put(IssuanceProtocolValues.capA, capA);
        issuanceProtocolValues.put(IssuanceProtocolValues.e, e);
        issuanceProtocolValues.put(IssuanceProtocolValues.vPrimePrime,
                vPrimePrime);

        URI updateSpecLocation = spec.getCredentialStructure()
                .getUpdateSpecLocation();
        URI updateLocation = null;

        if (updateSpecLocation != null) {

            UpdateSpecification updateSpec = (UpdateSpecification) StructureStore
                    .getInstance().get(updateSpecLocation);

            // note, the attStructs will not be needed for any other purpose, so
            // we re-use it
            attStructs = updateSpec.getCompliantAttributeSpecVector(attStructs);

            Values updatedValues = new Values(sp);
            for (AttributeStructure attStruct : attStructs) {
                if (attStruct.getIssuanceMode() != IssuanceMode.KNOWN) {
                    throw new RuntimeException("Only values that are known to "
                            + "the ISSUER can be updated.");
                }
                final String name = attStruct.getName();
                updatedValues.add(name, values.get(name).getContent());
            }
            updateLocation = getIndividualUpdateLocation(updateSpec
                    .getBaseLocation());
            issuerUpdateInformation = new IssuerUpdateInformation(
                    spec.getIssuerPublicKeyId(),
                    spec.getCredStructureLocation(), capQ, vPrimePrime,
                    updatedValues, updateLocation, nonce_recipient, context);

            log.log(Level.INFO, issuerUpdateInformation.toStringPretty());

            response = new Message(issuanceProtocolValues, p2, updateLocation);
        } else {
            response = new Message(issuanceProtocolValues, p2);
        }
        return response;
    }

    private static Proof computeATildeProof(Vector<BigInteger> proofContext,
            final SystemParameters sp, final BigInteger n,
            final BigInteger pPrime_qPrime, final BigInteger eInverse,
            final BigInteger capQ) {
        HashMap<String, SValue> sValues;
        final BigInteger r = Utils.computeRandomNumber(
                pPrime_qPrime.subtract(BigInteger.ONE), sp).add(BigInteger.ONE);
        final BigInteger capATilde = capQ.modPow(r, n);

        proofContext.add(capATilde);

        final BigInteger cPrime = Utils.hashOf(sp.getL_H(), proofContext);

        final BigInteger s_e = r.subtract(cPrime.multiply(eInverse)).mod(
                pPrime_qPrime);

        // creating new s-value map
        sValues = new HashMap<String, SValue>();
        sValues.put(IssuanceSpec.s_e, new SValue(s_e));
        final Proof p2 = new Proof(cPrime, sValues);
        return p2;
    }

    /**
     * @return Update location for the credential that is about to be issued.
     */
    private URI getIndividualUpdateLocation(URI baseUri) {
        return baseUri.resolve("Update_" + Utils.getRandomString(20) + ".xml");
    }

    /**
     * @param attStructs
     * @param sValues
     * @param capR
     * @param n
     * @param expos
     * @return Exponentiations for attributes.
     */
    private Vector<Exponentiation> addHatAttExpos(
            final Vector<? extends AttributeStructure> attStructs,
            final HashMap<String, SValue> sValues, final BigInteger[] capR,
            final BigInteger n) {
        final Vector<Exponentiation> expos = new Vector<Exponentiation>();

        for (AttributeStructure attStruct : attStructs) {
            if (attStruct.getIssuanceMode() == IssuanceMode.KNOWN) {
                continue;
            }
            final BigInteger mHat = (BigInteger) sValues.get(
                    attStruct.getName()).getValue();
            int keyIndex = attStruct.getKeyIndex();
            expos.add(new Exponentiation(capR[keyIndex], mHat, n));
            log.log(Level.FINE, "loading attribute: " + attStruct.getName());
        }
        return expos;
    }

    /**
     * @return Issuer update information, which contains all information (values
     *         and location information) that will allow issuing updates to this
     *         credential in the future.
     */
    public final IssuerUpdateInformation getIssuerUpdateInformation() {
        return issuerUpdateInformation;
    }

    /**
     * Computation of capQ.
     * 
     * @param capS
     * @param capU
     * @param capZ
     * @param capR
     * @param vPrimePrime
     * @param n
     * @return capQ
     */
    public static BigInteger computeQ(final BigInteger capS,
            final BigInteger capU, final BigInteger capZ,
            final BigInteger[] capR, final BigInteger vPrimePrime,
            final BigInteger n, Vector<AttributeStructure> attStructs,
            Values values) {

        BigInteger capQ;

        final Vector<Exponentiation> e = new Vector<Exponentiation>();

        for (AttributeStructure attStruct : attStructs) {
            e.add(new Exponentiation(capR[attStruct.getKeyIndex()],
                    (BigInteger) values.getValue(attStruct), n));
        }
        e.add(new Exponentiation(capS, vPrimePrime, n));

        capQ = Utils.multiExpMul(capU, e, n);
        capQ = capQ.modInverse(n);
        capQ = (capZ.multiply(capQ)).mod(n);

        return capQ;
    }

    /**
     * Updates a credential to the given values using the information from the
     * issuer record.
     * 
     * @param issuerKeyPair
     *            Key pair to be used.
     * @param values
     *            New values of known attributes (only a subset of the known
     *            attributes might be updated).
     * @param issuerRecord
     *            Issuer record containing the old attribute values as well as
     *            the required signature elements to update the signature.
     */
    public static Message updateCredential(final IssuerKeyPair issuerKeyPair,
            final Values values, final IssuerUpdateInformation issuerRecord) {
        IssuerPublicKey publicKey = issuerKeyPair.getPublicKey();
        IssuerPrivateKey privateKey = issuerKeyPair.getPrivateKey();
        SystemParameters sp = publicKey.getGroupParams().getSystemParams();

        BigInteger e, vTilde, vBarPrimePrime;

        log.log(Level.INFO, issuerRecord.toStringPretty());

        // [spec: UpdateCredential 1.2] choose values to update the signature
        e = Utils.chooseE(sp);
        vTilde = Utils.computeRandomNumber(sp.getL_v() - 1);
        vBarPrimePrime = vTilde.add(BigInteger.ONE.shiftLeft(sp.getL_v() - 1));
        BigInteger deltaVPrimePrime = vBarPrimePrime.subtract(issuerRecord
                .getVPrimePrime());
        BigInteger n = publicKey.getN();

        Values newValues = new Values(sp);
        Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(publicKey.getCapS(), deltaVPrimePrime, n));

        // get update specification to know which values should be updated
        Vector<AttributeStructure> attStructs = issuerRecord.getCredStruct()
                .getAttributeStructs(IssuanceMode.KNOWN);
        UpdateSpecification updateSpec = (UpdateSpecification) StructureStore
                .getInstance().get(
                        issuerRecord.getCredStruct().getUpdateSpecLocation());
        // check if all updated values are defined to be updateable
        updateSpec.verifyValues(values);
        attStructs = updateSpec.getCompliantAttributeSpecVector(attStructs);

        for (AttributeStructure attStruct : attStructs) {
            final String name = attStruct.getName();
            if (newValues.containsKey(name)) {
                throw new RuntimeException("Value: " + name + " is updated "
                        + "twice within one update run. Please only provide "
                        + "one update value per attribute.");
            }
            final BigInteger mBar_i = (BigInteger) values.getValue(attStruct);
            BigInteger deltaM_i = mBar_i.subtract(issuerRecord.getValue(name));
            expos.add(new Exponentiation(publicKey.getCapR()[attStruct
                    .getKeyIndex()], deltaM_i, n));
            newValues.add(name, mBar_i);
        }
        BigInteger divisor = Utils.multiExpMul(expos, n).modInverse(n);
        BigInteger capQBar = issuerRecord.getCapQ().multiply(divisor).mod(n);

        BigInteger pPrime_qPrime = privateKey.computeQPrimePPrime();
        BigInteger eInverse = e.modInverse(pPrime_qPrime);
        BigInteger capABar = capQBar.modPow(eInverse, n);

        // [spec: UpdateCredential 1.3] create the proof.
        Vector<BigInteger> proofContext = new Vector<BigInteger>();
        proofContext.add(issuerRecord.getContext());
        proofContext.add(capQBar);
        proofContext.add(capABar);
        proofContext.add(issuerRecord.getNonce());

        final Proof p2 = computeATildeProof(proofContext, sp, n, pPrime_qPrime,
                eInverse, capQBar);

        issuerRecord.update(capQBar, vBarPrimePrime, newValues);

        log.log(Level.INFO, issuerRecord.toStringPretty());

        HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
        issuanceProtocolValues = new HashMap<Message.IssuanceProtocolValues, BigInteger>();
        issuanceProtocolValues.put(IssuanceProtocolValues.capA, capABar);
        issuanceProtocolValues.put(IssuanceProtocolValues.e, e);
        issuanceProtocolValues.put(IssuanceProtocolValues.vPrimePrime,
                vBarPrimePrime);
        // issuanceProtocolValues.put(IssuanceProtocolValues.capQ, capQBar);

        return new Message(issuanceProtocolValues, p2);
    }
}
