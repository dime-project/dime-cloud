/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.predicates;

import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.StructureStore;

/**
 * This predicate expresses proofs of knowledge about credentials. It uses a
 * credential and a map from attribute names to identifiers to determine over
 * which attributes it should issue equality proofs.
 */
public class CLPredicate extends Predicate {

    /** Identifier of the issuer public key associated with this predicate. */
    private final URI issuerPublicKeyId;
    /** Identifier of the credential structure associated to this predicate. */
    private final URI credStructId;
    /** Temporary name of the credential as used in the proof specification. */
    private final String credName;
    /** Map from attribute names to identifiers used in this predicate. */
    private HashMap<String, Identifier> attToIdentifierMap;

    /**
     * Constructor.
     * 
     * @param ipkId
     *            Identifier of the issuer public key associated to this
     *            predicate.
     * @param theCredStructId
     *            Location of the credential structure associated to this
     *            predicate.
     * @param theCredName
     *            Temporary name of the credential as used in the proof
     *            specification.
     * @param attToIds
     *            Map from attribute names to identifiers used in this
     *            predicate.
     */
    public CLPredicate(final URI ipkId, final URI theCredStructId,
            final String theCredName, final HashMap<String, Identifier> attToIds) {
        super(PredicateType.CL);

        issuerPublicKeyId = ipkId;
        credStructId = theCredStructId;
        credName = theCredName;
        attToIdentifierMap = attToIds;
    }

    /**
     * @param attName
     *            Name of the attribute associated with some identifier.
     * @return Identifier associated with the given <code>attName</code>.
     */
    public final Identifier getIdentifier(final String attName) {
        return attToIdentifierMap.get(attName);
    }

    /**
     * @return Temporary name for the credential associated with this predicate.
     *         The name consists of a concatenation of the structure location
     *         and the credential name given in the proof specification.
     */
    public final String getTempCredName() {
        return credStructId.toString().concat(Constants.DELIMITER)
                .concat(credName);
    }

    /**
     * @return Credential structure location of the credential associated with
     *         this predicate.
     */
    public final URI getCredStructLocation() {
        return credStructId;
    }

    /**
     * @return Issuer public key identifier of the credential associated with
     *         this predicate.
     */
    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }

    /**
     * Convenience method.
     * 
     * @return Issuer public key object.
     */
    public final IssuerPublicKey getIssuerPublicKey() {
        return (IssuerPublicKey) StructureStore.getInstance().get(
                issuerPublicKeyId);
    }

    /**
     * @return Human-readable string of this predicate.
     */
    public final String toStringPretty() {
        String s = "CLPredicate( " + credStructId + Constants.DELIMITER
                + credName + ")\n";
        Iterator<String> iterator = attToIdentifierMap.keySet().iterator();
        while (iterator.hasNext()) {
            String attName = iterator.next();
            s += "\t(" + attName + " -> "
                    + attToIdentifierMap.get(attName).getName() + ")\n";
        }
        return s;
    }
}
