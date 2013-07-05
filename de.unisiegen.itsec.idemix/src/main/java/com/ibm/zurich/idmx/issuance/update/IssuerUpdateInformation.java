/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.issuance.update;

import java.math.BigInteger;
import java.net.URI;
import java.util.Iterator;

import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Data persisted by issuer after issuing a credential, in order to create an
 * update for the credential later.
 */
public class IssuerUpdateInformation {

    /** Issuer public key of the credential update. */
    private final URI issuerPublicKeyId;
    /** Credential structure of the credential update. */
    private final URI credStructLocation;
    /** <tt>Q</tt> as generated during issuance. */
    private BigInteger capQ;
    /** <tt>v''</tt> chosen during issuance. */
    private BigInteger vPrimePrime;
    /** Values of the known attributes. */
    private Values values;
    /** Location where the update will be collected. */
    private URI updateLocation;

    /** Nonce from issuing that is needed as message in the proof. */
    private BigInteger nonce_recipient;
    /** Context from issuing that is needed as message in the proof. */
    private BigInteger context;

    /**
     * Constructor.
     * 
     * @param theCredStructLocation
     *            Credential structure of the credential update.
     * @param theCapQ
     *            <tt>Q</tt> as generated during issuance.
     * @param theVPrimePrime
     *            <tt>v''</tt> chosen during issuance.
     * @param theValues
     *            Values of the known attributes.
     * @param theUpdateLocation
     *            Location where the update will be collected.
     */
    public IssuerUpdateInformation(final URI ipkId,final URI theCredStructLocation,
            final BigInteger theCapQ, final BigInteger theVPrimePrime,
            final Values theValues, final URI theUpdateLocation,
            final BigInteger theNonce_recipient, final BigInteger theContext) {
        issuerPublicKeyId = ipkId;
        credStructLocation = theCredStructLocation;
        capQ = theCapQ;
        vPrimePrime = theVPrimePrime;
        values = theValues;
        updateLocation = theUpdateLocation;
        nonce_recipient = theNonce_recipient;
        context = theContext;
    }

    /**
     * @return <tt>v''</tt>.
     */
    public final BigInteger getVPrimePrime() {
        return vPrimePrime;
    }

    /**
     * @return <tt>Q</tt>.
     */
    public final BigInteger getCapQ() {
        return capQ;
    }

    /**
     * @return Nonce from the issuing protocol.
     */
    public final BigInteger getNonce() {
        return nonce_recipient;
    }

    /**
     * @return Context from the issuing protocol.
     */
    public final BigInteger getContext() {
        return context;
    }

    /**
     * @return Credential structure that corresponds to this credential update.
     */
    public final CredentialStructure getCredStruct() {
        return (CredentialStructure) StructureStore.getInstance().get(
                credStructLocation);
    }

    /**
     * Serialization method.
     */
    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }
    
    /**
     * Serialization method.
     */
    public final URI getCredStructLocation() {
        return credStructLocation;
    }
    
    /**
     * Serialization method.
     */
    public final URI getUpdateLocation() {
        return updateLocation;
    }
    
    /**
     * Serialization method.
     */
    public final Values getValues() {
        return values;
    }

    /**
     * @param name
     *            Name of a known attribute.
     * @return Value of the attribute.
     */
    public final BigInteger getValue(final String name) {
        return (BigInteger) values.get(name).getContent();
    }

    /**
     * Updates this issuance record such that it corresponds to the updated
     * credential.
     * 
     * @param capQBar
     *            New value for <tt>Q</tt>.
     * @param vBarPrimePrime
     *            New value for <tt>v''</tt>.
     * @param newValues
     *            New attributes values.
     * 
     */
    public final void update(final BigInteger capQBar,
            final BigInteger vBarPrimePrime, final Values newValues) {
        capQ = capQBar;
        vPrimePrime = vBarPrimePrime;
        values = newValues;
    }

    /**
     * Creates a string with a human-readable description of this object.
     * 
     * @return string containing the most important elements of this object.
     */
    public final String toStringPretty() {
        String endl = System.getProperty("line.separator");

        String s = "Issuer Update Record:" + endl;
        s += "\tcapQ:" + Utils.logBigInt(capQ) + endl;
        s += "\tvPrimePrime: " + Utils.logBigInt(vPrimePrime) + endl;
        s += "\tupdateLocation: " + updateLocation.toString() + endl;
        s += "\tKnown values..." + endl;
        s += "\t\t( Name \tValue)" + endl;
        Iterator<String> it = values.iterator();
        while (it.hasNext()) {
            String name = it.next();
            BigInteger value = (BigInteger) values.get(name).getContent();
            s += "\t\t" + name + "\t" + Utils.logBigInt(value) + endl;
        }
        return s;
    }
}
