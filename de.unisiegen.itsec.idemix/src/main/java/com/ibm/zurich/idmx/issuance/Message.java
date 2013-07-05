/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.issuance;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;

import com.ibm.zurich.idmx.showproof.Proof;

/**
 *
 */
public class Message {

    public enum IssuanceProtocolValues {
        /** Common value <tt>U</tt>. */
        capU,
        /** Nonce. */
        nonce,

        /** Signature value <tt>A</tt>. */
        capA,
        /** Signature value <tt>e</tt>. */
        e,
        /** Signature value <tt>v''</tt>. */
        vPrimePrime,
    }

    /** Map with all the elements of the message. */
    private final HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
    /** Proof. */
    private final Proof proof;
    /** Location where the updates for a credential can be downloaded. */
    private final URI updateLocation;

    /**
     * Convenience constructor.
     */
    public Message(
            HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof) {
        this(theIssuanceElements, theProof, null);
    }

    /**
     * Constructor.
     * 
     * @param theIssuanceElements
     *            Values generated during a protocol step that need to be
     *            communicated to the communication partner.
     * @param theProof
     *            Relevant values of the proof convincing the communication
     *            partner to continue the protocol.
     * @param theUpdateLocation
     *            [optional] If the credential is updateable, the location where
     *            updates can be fetched needs to be sent to the RECIPIENT.
     */
    public Message(
            HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof, URI theUpdateLocation) {
        issuanceProtocolValues = theIssuanceElements;
        proof = theProof;
        updateLocation = theUpdateLocation;
    }

    /**
     * @return The issuance element queried for (e.g., <tt>A</tt>, <tt>e</tt>,
     *         <tt>v''</tt>, <tt>Q</tt>).
     */
    public final BigInteger getIssuanceElement(IssuanceProtocolValues element) {
        return issuanceProtocolValues.get(element);
    }

    /**
     * @return Proof.
     */
    public final Proof getProof() {
        return proof;
    }

    /**
     * @return Location where the credential update can be downloaded.
     */
    public final URI getUpdateLocation() {
        return updateLocation;
    }

    /**
     * Serialization method.
     */
    public final Iterator<IssuanceProtocolValues> iterator() {
        return issuanceProtocolValues.keySet().iterator();
    }
}
