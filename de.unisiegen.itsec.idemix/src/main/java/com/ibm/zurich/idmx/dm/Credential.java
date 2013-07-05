/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.DataType;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Credential abstraction. When persisted by the recipient, all attribute values
 * are set. When we use a certificate in a show-proof on the verifier side, the
 * attribute values must be nullified.
 * 
 */
public class Credential {

    /** Update information needed to update the signature. */
    public class UpdateInformation {
        private final BigInteger capU;
        private final BigInteger vPrime;
        private final URI updateLocation;
        private final BigInteger nonce;
        private final BigInteger context;

        public UpdateInformation(final BigInteger theCapU,
                final BigInteger theVPrime, final URI theUpdateLocation,
                final BigInteger theNonce, final BigInteger theContext) {
            capU = theCapU;
            vPrime = theVPrime;
            updateLocation = theUpdateLocation;
            nonce = theNonce;
            context = theContext;
            // update the update information reference of the credential
            updateInformation = this;
        }

        public final BigInteger getCapU() {
            return capU;
        }

        public final BigInteger getVPrime() {
            return vPrime;
        }

        public final URI getUpdateLocation() {
            return updateLocation;
        }

        public final BigInteger getNonce() {
            return nonce;
        }

        public final BigInteger getContext() {
            return context;
        }
    }

    /** Logger. */
    private static Logger log = Logger.getLogger(Credential.class.getName());

    /** The ID of the issuer public key used to issue this credential. */
    private final URI issuerPublicKeyId;
    /** Public key of the issuer of this credential. */
    private final IssuerPublicKey ipk;
    /** Credential structure that corresponds to this credential. */
    private final URI credStructId;
    /** Set of attributes of any issuance mode (hidden, known or committed). */
    private final List<Attribute> attributes;

    /** Master secret of the current credential. */
    private MasterSecret masterSecret;

    /** CL certificate signature value called <tt>A</tt>. */
    private BigInteger capA;
    /** CL certificate signature value called <tt>e</tt>. */
    private BigInteger e;
    /** CL certificate signature value called <tt>v</tt>. */
    private BigInteger v;

    /** Indicates if the epoch feature is used. */
    private final boolean haveEpoch;

    /** Update information. */
    private UpdateInformation updateInformation;

    /**
     * Constructor used for loading credential from XML.
     * 
     * @param ipkId
     *            Identifier of the issuer public key.
     * @param theCredStructId
     *            Identifier of the credential structure.
     * @param theCapA
     *            Signature value <tt>A</tt>.
     * @param theE
     *            Signature value <tt>e</tt>.
     * @param theV
     *            Signature value <tt>v</tt>.
     * @param theAttributes
     *            Attribute values.
     */
    public Credential(final URI ipkId, final URI theCredStructId,
            final BigInteger theCapA, final BigInteger theE,
            final BigInteger theV, final Vector<Attribute> theAttributes) {

        capA = theCapA;
        e = theE;
        v = theV;

        issuerPublicKeyId = ipkId;
        credStructId = theCredStructId;

        ipk = (IssuerPublicKey) StructureStore.getInstance().get(
                issuerPublicKeyId);

        attributes = theAttributes;

        if (getEpoch() != null) {
            haveEpoch = true;
        } else {
            haveEpoch = false;
        }
    }

    /**
     * Constructor. Create a credential object. Input is a CL signature
     * <tt>(A,e,v)</tt>, a credential structure (containing issuer public key,
     * group parameters, ...) and the values that will be assigned to the
     * attributes in the newly created credential.
     * 
     * @param ipkId
     *            Identifier of the issuer public key.
     * @param theCredStructLocation
     *            Location of the credential structure.
     * @param theCapA
     *            Signature value <tt>A</tt>.
     * @param theE
     *            Signature value <tt>e</tt>.
     * @param theV
     *            Signature value <tt>v</tt>.
     * @param values
     *            Values of the attributes that will be contained in the
     *            credential.
     * @param theMasterSecret
     *            Master secret object.
     */
    public Credential(final URI ipkId, final URI theCredStructLocation,
            final BigInteger theCapA, final BigInteger theE,
            final BigInteger theV, final Values values,
            final MasterSecret theMasterSecret) {
        // Signature
        capA = theCapA;
        e = theE;
        v = theV;

        issuerPublicKeyId = ipkId;
        credStructId = theCredStructLocation;

        CredentialStructure credStruct = (CredentialStructure) StructureStore
                .getInstance().get(credStructId);

        // dependent values for convenience
        ipk = (IssuerPublicKey) StructureStore.getInstance().get(
                issuerPublicKeyId);

        // create attributes using the given information
        attributes = credStruct.createAttributes(values);
        masterSecret = theMasterSecret;
        if (!verifySignature()) {
            throw (new RuntimeException("Signature verification failed. "
                    + "Credential cannot be created"));
        }

        // set the epoch flag.
        if (this.getEpoch() != null) {
            haveEpoch = true;
        } else {
            haveEpoch = false;
        }

        if (!verifyCredential()) {
            throw new RuntimeException("Credential does not comply with "
                    + "the given structure.");
        }
    }

    /**
     * Verifies the CL signature of this credential.
     */
    public boolean verifySignature() {
        final BigInteger[] capR = ipk.getCapR();
        final BigInteger n = ipk.getN();

        final Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(capA, e, n));
        expos.add(new Exponentiation(ipk.getCapS(), v, n));
        // add attribute exponentiations
        for (Attribute att : attributes) {
            int keyIndex = att.getKeyIndex();
            assert (keyIndex >= 0 && keyIndex < capR.length);

            expos.add(new Exponentiation(capR[keyIndex], att.getValue(), n));
        }
        final BigInteger capZHatPrime = Utils.multiExpMul(expos, n);
        final BigInteger capZHat = masterSecret.getCapU(capZHatPrime,
                ipk.getCapR()[IssuanceSpec.MASTER_SECRET_INDEX], ipk.getN());

        if (!capZHat.equals(ipk.getCapZ())) {
            log.log(Level.SEVERE, "ZHat not equal Z");
            return false;
        }
        return true;
    }

    /**
     * Verify a credential upon validity with respect to this credential
     * structure.
     * 
     * @param cred
     *            The credential to be analyzed.
     * @return True if the credential matches the credential structure.
     */
    private final boolean verifyCredential() {
        CredentialStructure credStruct = (CredentialStructure) StructureStore
                .getInstance().get(credStructId);
        HashSet<String> queriedAtts = new HashSet<String>();
        for (Attribute att : attributes) {
            if (credStruct.getAttributeStructure(att.getName()) != null) {
                queriedAtts.add(att.getName());
            }
        }
        for (AttributeStructure attStruct : credStruct.getAttributeStructs()) {
            if (!queriedAtts.contains(attStruct.getName())) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return Public key of the issuer of this certificate.
     */
    public final IssuerPublicKey getPublicKey() {
        return ipk;
    }

    /**
     * @return Identifier of the credential structure.
     */
    public final URI getCredStructId() {
        return credStructId;
    }

    /**
     * @return Identifier of the issuer public key.
     */
    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }

    /**
     * @return Signature value <tt>e</tt>.
     */
    public final BigInteger getE() {
        return e;
    }

    /**
     * @return Signature value <tt>v</tt>.
     */
    public final BigInteger getV() {
        return v;
    }

    /**
     * @return Signature value <tt>A</tt>.
     */
    public final BigInteger getCapA() {
        return capA;
    }

    /**
     * @return True if the certificate contains an epoch.
     */
    public final boolean haveEpoch() {
        return haveEpoch;
    }

    /**
     * @return Epoch attribute of <code>null</code> if there is no epoch
     *         attribute found.
     */
    public final Attribute getEpoch() {
        for (Attribute att : attributes) {
            if (att.getDataType() == DataType.EPOCH) {
                return att;
            }
        }
        return null;
    }

    /**
     * @return Update information.
     */
    public final UpdateInformation getUpdateInformation() {
        return updateInformation;
    }

    /**
     * Update the signature of the certificate.
     * 
     * @param msg
     *            Message containing the new signature values <tt>A, e, v</tt>.
     * @param newValues
     *            New attributes.
     */
    public final void update(final Message msg, final Values newValues) {
        final BigInteger n = ipk.getN();
        final int l_H = ipk.getGroupParams().getSystemParams().getL_H();

        // [spec: UpdateCredential 2.1] 
        final BigInteger capABar = msg
                .getIssuanceElement(IssuanceProtocolValues.capA);
        final BigInteger capQ = capABar.modPow(
                msg.getIssuanceElement(IssuanceProtocolValues.e), n);

        // [spec: UpdateCredential 2.2] verify proof
        final Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(capABar, msg.getProof().getChallenge(), n));
        expos.add(new Exponentiation(capQ, (BigInteger) msg.getProof()
                .getSValue(IssuanceSpec.s_e).getValue(), n));
        final BigInteger capAHat = Utils.multiExpMul(expos, n);

        Vector<BigInteger> proofContext = new Vector<BigInteger>();
        proofContext.add(updateInformation.getContext());
        proofContext.add(capQ);
        proofContext.add(capABar);
        proofContext.add(updateInformation.getNonce());
        proofContext.add(capAHat);
        final BigInteger cHat = Utils.hashOf(l_H, proofContext);

        if (!cHat.equals(msg.getProof().getChallenge())) {
            throw new RuntimeException("Verification failure! "
                    + "Mismatching cPrime, cHat");
        }

        // update credential
        capA = capABar;
        e = msg.getIssuanceElement(IssuanceProtocolValues.e);
        v = msg.getIssuanceElement(IssuanceProtocolValues.vPrimePrime).add(
                updateInformation.getVPrime());

        Iterator<String> newValuesNames = newValues.iterator();
        while (newValuesNames.hasNext()) {
            String attName = newValuesNames.next();
            BigInteger attValue = (BigInteger) newValues.get(attName)
                    .getContent();

            Attribute att = getAttribute(attName);
            if (att == null) {
                throw (new RuntimeException("Wrong credential update: "
                        + "attribute " + attName + " not found."));
            }
            if (att.getIssuanceMode() != IssuanceMode.KNOWN) {
                throw (new RuntimeException("Wrong credential update: "
                        + "attribute " + attName + " is not a known "
                        + "attribute."));
            }
            att.setValue(attValue);
        }
    }

    /**
     * Returns the set of attributes of this credential. Note that the master
     * secret is not part of this set.
     * 
     * @return Set of attributes.
     */
    public final List<Attribute> getAttributes() {
        return attributes;
    }

    /**
     * @param attName
     *            Attribute's name.
     * @return Attribute or <code>null</code> if no attribute with the given
     *         name is found.
     */
    public final Attribute getAttribute(final String attName) {
        for (int i = 0; i < attributes.size(); i++) {
            final Attribute a = attributes.get(i);
            if (attName.equalsIgnoreCase(a.getName())) {
                return a;
            }
        }
        return null;
    }

    /**
     * Creates a string with a human-readable description of this object.
     * 
     * @return string containing the most important elements of this object.
     */
    public final String toStringPretty() {
        String endl = System.getProperty("line.separator");

        String s = "Credential Information:" + endl;
        s += "\tSignature..." + endl;
        s += "\t\tcapA: " + Utils.logBigInt(capA) + endl;
        s += "\t\te: " + Utils.logBigInt(e) + endl;
        s += "\t\tv: " + Utils.logBigInt(v) + endl;
        s += "\tNumber of attributes:" + attributes.size() + endl;
        s += "\t\t( Name: \tIndex: \tDataType: \tValue [ev. primes])" + endl;
        for (int i = 0; i < attributes.size(); i++) {
            Attribute a = attributes.get(i);
            assert (a != null);
            s += "\t\t" + a.toStringPretty() + endl;
        }
        s += ipk.toStringPretty();
        return s;
    }

    // /**
    // * Persist credential to the given file name.
    // *
    // * @param fn
    // * File name.
    // * @return True if serialization is successful, false otherwise.
    // */
    // public final boolean save(final String fn) {
    // return Serializer.serialize(fn, this);
    // }
    //
    // /**
    // * @param fn
    // * File name used to load the document.
    // * @return Credential object loaded from the given file.
    // * @deprecated Credentials must be serialized into XML objects.
    // */
    // public static Credential getCredential(final String fn) {
    //
    // Credential cred = (Credential) Serializer.deserialize(fn,
    // Credential.class);
    // if (cred == null) {
    // log.log(Level.SEVERE, "failure to deserialize certificate");
    // return null;
    // }
    // return cred;
    // }

    // @Override
    // public boolean equals(final Object obj) {
    // if (this == obj) {
    // return true;
    // }
    // if (obj == null) {
    // return false;
    // }
    // if (getClass() != obj.getClass()) {
    // return false;
    // }
    // Credential other = (Credential) obj;
    // if (attributes == null) {
    // if (other.attributes != null) {
    // return false;
    // }
    // } else if (!attributes.equals(other.attributes)) {
    // return false;
    // }
    // if (capA == null) {
    // if (other.capA != null) {
    // return false;
    // }
    // } else if (!capA.equals(other.capA)) {
    // return false;
    // }
    // if (e == null) {
    // if (other.e != null) {
    // return false;
    // }
    // } else if (!e.equals(other.e)) {
    // return false;
    // }
    // if (gp == null) {
    // if (other.gp != null) {
    // return false;
    // }
    // } else if (!gp.equals(other.gp)) {
    // return false;
    // }
    // if (haveEpoch != other.haveEpoch) {
    // return false;
    // }
    // if (ipk == null) {
    // if (other.ipk != null) {
    // return false;
    // }
    // } else if (!ipk.equals(other.ipk)) {
    // return false;
    // }
    // if (nonRevealedAttrs == null) {
    // if (other.nonRevealedAttrs != null) {
    // return false;
    // }
    // } else if (!nonRevealedAttrs.equals(other.nonRevealedAttrs)) {
    // return false;
    // }
    // if (revealedAttrs == null) {
    // if (other.revealedAttrs != null) {
    // return false;
    // }
    // } else if (!revealedAttrs.equals(other.revealedAttrs)) {
    // return false;
    // }
    // // if (type == null) {
    // // if (other.type != null) {
    // // return false;
    // // }
    // // } else if (!type.equals(other.type)) {
    // // return false;
    // // }
    // // if (uuid == null) {
    // // if (other.uuid != null) {
    // // return false;
    // // }
    // // } else if (!uuid.equals(other.uuid)) {
    // // return false;
    // // }
    // if (v == null) {
    // if (other.v != null) {
    // return false;
    // }
    // } else if (!v.equals(other.v)) {
    // return false;
    // }
    // return true;
    // }

}
