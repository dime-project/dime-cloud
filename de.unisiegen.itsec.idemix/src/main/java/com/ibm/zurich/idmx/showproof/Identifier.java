/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.DataType;
import com.ibm.zurich.idmx.utils.StructureStore;

/**
 * Object used to implement identifiers for hidden and revealed values,
 * commitments and verifiable encryptions in the proof specification.
 */
public class Identifier {

    /** All possible types of identifiers. */
    public enum ProofMode {
        /** Attributes that are hidden from the verifier. */
        UNREVEALED,
        /** Attributes that are revealed to the verifier. */
        REVEALED,
        /** Commitment. */
        COMMITMENT,
        /** Verifiable encryption. */
        VERENC,
        /** Pseudonym. */
        NYM,
        /** Message. */
        MESSAGE
    };

    /** Name used to refer to this identifier. */
    private String name;
    /** Data type of the value. */
    private DataType dataType;
    /** Mode under which the identifier is proved (i.e., hidden, revealed). */
    private final ProofMode proofMode;

    /** Random used for the commitments to this identifier. */
    private BigInteger rand;
    /**
     * A reference to the attribute that contains the value of this identifier.
     * This reference is only used on the PROVER's side.
     */
    private Attribute attr;

    /**
     * References the attribute structure that this identifier belongs to. This
     * is required for prime encoded attributes. This reference is only used on
     * the VERIFIER's side.
     */
    private URI credentialStructureId;
    private URI issuerPublicKeyId;
    private String attributeName;

    /**
     * Value of the identifier, which is needed in case this is the second
     * argument of an inequality predicate.
     */
    private BigInteger value;

    /**
     * Creates an identifier with the given name, data type (as specified by the
     * attribute structure class) and type.
     * 
     * @param attributeIdName
     *            The name of the identifier.
     * @param theDataType
     *            The data type of the attribute.
     * @param theProofMode
     *            The proof mode of the attribute (e.g., REVEALED).
     */
    public Identifier(final String attributeIdName, final DataType theDataType,
            final ProofMode theProofMode) {
        name = attributeIdName;
        dataType = theDataType;
        proofMode = theProofMode;
    }

    /**
     * @return The name of this identifier.
     */
    public final String getName() {
        return name;
    }

    /**
     * Sets the name of the identifier.
     * 
     * @param attributeIdName
     *            The new name that is assigned to the attribute identifier.
     */
    public final void setName(final String attributeIdName) {
        name = attributeIdName;
    }

    /**
     * @return The data type (as defined in the Attribute class).
     */
    public final DataType getDataType() {
        return dataType;
    }

    /**
     * @return Attribute structure corresponding to this identifier.
     */
    public final AttributeStructure getAttStruct() {
        if (attr != null) {
            return attr.getStructure();
        } else {
            CredentialStructure credStruct = (CredentialStructure) StructureStore
                    .getInstance().get(credentialStructureId);
            return credStruct.getAttributeStructure(attributeName);
        }
    }

    /**
     * @return True if this identifier will be revealed during the proof.
     */
    public final boolean isRevealed() {
        return (proofMode == ProofMode.REVEALED);
    }

    /**
     * @return True if this identifier will NOT be revealed during the proof.
     */
    public final boolean isUnrevealed() {
        return (proofMode == ProofMode.UNREVEALED);
    }

    /**
     * Sets the randomness to be used with this identifier.
     * 
     * @param random
     *            The randomness that is used with this identifier.
     */
    public final void setRandom(final BigInteger random) {
        rand = random;
    }

    /**
     * @return The randomness used for this identifier.
     */
    public final BigInteger getRandom() {
        return rand;
    }

    /**
     * Sets the attribute that corresponds to this identifier.
     * 
     * @param attribute
     *            The attribute containing the secret values.
     */
    public final void setAttr(final Attribute attribute) {
        attr = attribute;
    }

    /**
     * @return Value of the attribute it represents.
     */
    public final BigInteger getValue() {
        if (attr != null) {
            return attr.getValue();
        } else {
            return value;
        }
    }

    public final void setValue(final BigInteger theValue) {
        value = theValue;
    }

    public final void setAttributeName(final String ipkId,
            final String credStructId, final String attName) {
        try {
            issuerPublicKeyId = new URI(ipkId);
            credentialStructureId = new URI(credStructId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        attributeName = attName;
    }

    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }

    /**
     * Checks if a given identifier is contained in a vector of identifiers.
     * 
     * @param attIds
     *            Vector of identifiers.
     * @param attId
     *            Identifier to be checked.
     * @return True if the string name of <tt>attId</tt> appears in the vector
     *         of identifiers.
     */
    public static final boolean contains(final Vector<Identifier> attIds,
            final Identifier attId) {
        for (Identifier v : attIds) {
            if (v.getName() == attId.getName()) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return A human readable version of this identifier.
     */
    public final String toStringPretty() {
        return "(" + name + " : " + dataType + " : " + proofMode + ")";
    }

    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj == null) || (getClass() != obj.getClass())) {
            return false;
        }

        Identifier other = (Identifier) obj;
        if (dataType != other.dataType) {
            return false;
        }
        if ((name == null) && (other.name != null)) {
            return false;
        } else if (!name.equals(other.name)) {
            return false;
        }
        if ((proofMode == null) && (other.proofMode != null)) {
            return false;
        } else if (!proofMode.equals(other.proofMode)) {
            return false;
        }
        return true;
    }

    @Override
    public final int hashCode() {
        int tmp = dataType.hashCode();
        tmp += name.hashCode();
        tmp += proofMode.hashCode();
        return tmp;
    }

    /**
     * Displays the contents of a list of identifiers.
     * 
     * @param attIds
     *            Vector of Identifiers.
     * @return String representation of the given identifiers.
     */
    public static String idsToString(final Vector<Identifier> attIds) {
        if (attIds == null || attIds.size() == 0) {
            return "none";
        }

        String s = "";
        for (int i = 0; i < attIds.size(); i++) {
            s += attIds.elementAt(i).getName();
            if (i < attIds.size() - 1) {
                s += ", ";
            }
        }
        return s;
    }
}
