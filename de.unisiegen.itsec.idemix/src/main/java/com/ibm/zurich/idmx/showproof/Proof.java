/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;

/**
 * Data structure for a proof.
 */
public class Proof {

    /** Challenge. */
    private final BigInteger challenge;
    /** S-values of the proof. */
    private final Map<String, SValue> values;
    /** List of common values. */
    private final TreeMap<String, BigInteger> commonList;
    /** List of verifiable encryptions. */
    private final TreeMap<String, VerifiableEncryption> verEncs;

    /**
     * Convenience constructor.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> theValues) {
        this(theChallenge, theValues, new TreeMap<String, BigInteger>(),
                new TreeMap<String, VerifiableEncryption>());
    }

    /**
     * Convenience constructor.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> theValues,
            final TreeMap<String, BigInteger> theCommonList) {
        this(theChallenge, theValues, theCommonList,
                new TreeMap<String, VerifiableEncryption>());
    }

    /**
     * @param theChallenge
     *            Challenge.
     * @param theValues
     *            S-values of the proof.
     * @param theCommonList
     *            List of common values.
     * @param theVerEncs
     *            List of verifiable encryptions.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> theValues,
            final TreeMap<String, BigInteger> theCommonList,
            final TreeMap<String, VerifiableEncryption> theVerEncs) {
        challenge = theChallenge;
        values = theValues;
        commonList = theCommonList;
        verEncs = theVerEncs;
    }

    /**
     * @param name
     *            Identifying name of the s-value.
     * @return S-value corresponding to the given <code>identifier</code>.
     */
    public final SValue getSValue(final String name) {
        return values.get(name);
    }

    /**
     * @return Challenge.
     */
    public final BigInteger getChallenge() {
        return challenge;
    }

    /**
     * @return List of common values.
     */
    public final TreeMap<String, BigInteger> getCommonList() {
        return commonList;
    }

    /**
     * @param name
     *            Name of the common value.
     * @return Common value with the given name.
     */
    public final BigInteger getCommonValue(final String name) {
        return commonList.get(name);
    }

    /**
     * Find the verifiable encryption associated to the verifiable encryption
     * predicate named "name".
     * 
     * @param name
     *            Name of the verifiable encryption.
     * @return the encryption object called "name" or null if not found.
     */
    public final VerifiableEncryption getVerEnc(final String name) {
        VerifiableEncryption enc = verEncs.get(name);
        if (verEncs == null || enc == null) {
            throw new RuntimeException("Verifiable encryption: " + name
                    + " not found.");
        }
        return enc;
    }

    /**
     * Serialisation method.
     */
    public final Map<String, SValue> getSValues() {
        return values;
    }

    /**
     * Serialisation method.
     */
    public final TreeMap<String, VerifiableEncryption> getVerEncs() {
        return verEncs;
    }
}
