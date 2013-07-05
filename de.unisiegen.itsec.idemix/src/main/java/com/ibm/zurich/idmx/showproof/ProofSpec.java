/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Proof specification object as parsed from the corresponding XML file.
 */
public class ProofSpec {

    /** Group parameters. */
    private GroupParameters gp = null;
    /** Map of identifiers used for the proof. */
    private HashMap<String, Identifier> identifierMap;
    /** Predicates. */
    private final Vector<Predicate> predicates;

    /**
     * Constructor for proof specifications. Null arguments are initialized as
     * length zero Vectors. The credentials will be cleared of private
     * information using Credential.eraseAttributeValues()
     * 
     * @param theIdentifierMap
     *            Map between identifier names and identifiers.
     * @param thePredicates
     *            Vector of predicates.
     */
    public ProofSpec(final HashMap<String, Identifier> theIdentifierMap,
            final Vector<Predicate> thePredicates) {
        assert (thePredicates != null);

        predicates = thePredicates;
        identifierMap = theIdentifierMap;

        validate();
    }

    /**
     * Validation of the proof specification. If any of the validation steps
     * fails, the method throws an exception and no proof specification is
     * created. The validation includes:
     * <ul>
     * <li>(CLPredicate) All attributes have a corresponding identifier.</li>
     * <li>(CLPredicate) Data type of attribute and identifier match.</li>
     * <li>(CLPredicate) Group parameters of all given credentials match.</li>
     * </ul>
     */
    private void validate() {
        Iterator<Predicate> iterator = predicates.iterator();
        while (iterator.hasNext()) {
            Predicate pred = iterator.next();

            // TODO (pbi) check that all Identifiers get assigned a value
            // in some CLPredicate or appear in a RepresentationPredicate

            switch (pred.getPredicateType()) {
            case CL:
                CLPredicate predicate = (CLPredicate) pred;
                CredentialStructure credStruct = (CredentialStructure) StructureStore
                        .getInstance().get(predicate.getCredStructLocation());

                Iterator<AttributeStructure> attStructs = credStruct
                        .getAttributeStructs().iterator();
                while (attStructs.hasNext()) {
                    AttributeStructure attStruct = attStructs.next();
                    String attName = attStruct.getName();
                    Identifier identifier = predicate.getIdentifier(attName);
                    // verify that attributes have a corresponding identifier
                    if (identifier == null) {
                        throw new RuntimeException("No identifier for "
                                + "attribute " + attName + " declared.");
                    }
                    // verify that data type of attribute and identifier match
                    if (identifier.getDataType() != attStruct.getDataType()) {
                        throw new RuntimeException("Wrong data type: "
                                + attName + " <> " + identifier.getName());
                    }
                }
                GroupParameters groupParams = predicate.getIssuerPublicKey()
                        .getGroupParams();
                if (gp == null) {
                    gp = groupParams;
                } else {
                    if (!gp.equals(groupParams)) {
                        throw new RuntimeException("Inconsistent group "
                                + "parameters.");
                    }
                }
                break;
            default:
            }
        }
    }

    /**
     * @return Group parameters that all the referenced credentials share.
     */
    public final GroupParameters getGroupParams() {
        return gp;
    }

    /**
     * @return Predicates from this specification.
     */
    public final Vector<Predicate> getPredicates() {
        return predicates;
    }

    /**
     * @return Identifiers used for this proof.
     */
    public final Collection<Identifier> getIdentifiers() {
        return identifierMap.values();
    }

    /**
     * @return Temporary name of a credential used to distinguish between
     *         different credentials of the same credential type and from the
     *         same issuer used in one proof.
     */
    public HashSet<String> getCredTempNames() {
        HashSet<String> credTempNames = new HashSet<String>();
        Iterator<Predicate> iterator = predicates.iterator();
        while (iterator.hasNext()) {
            Predicate pred = iterator.next();

            switch (pred.getPredicateType()) {
            case CL:
                credTempNames.add(((CLPredicate) pred).getTempCredName());
            }
        }
        return credTempNames;
    }

    /**
     * To get spec's context value.
     * 
     * @return value of spec's context.
     */
    public final BigInteger getContext() {
        Vector<BigInteger> contextVector = new Vector<BigInteger>();

        // add values of group parametes
        contextVector = Utils.computeGroupParamContext(gp, contextVector);

        // add values of all issuer public keys (possibly multiple times)
        Iterator<Predicate> it = predicates.iterator();
        while (it.hasNext()) {
            Predicate predicate = it.next();
            if (predicate instanceof CLPredicate) {
                IssuerPublicKey pk = ((CLPredicate) predicate)
                        .getIssuerPublicKey();
                contextVector = Utils.computeKeyContext(pk, contextVector);
            }
        }

        return Utils.hashOf(gp.getSystemParams().getL_H(), contextVector);
    }

    /**
     * @return Human-readable description of this object.
     */
    public final String toStringPretty() {
        String endl = System.getProperty("line.separator");
        String s = "-----------------" + endl + "Proof Specification:" + endl;

        s += "Identifiers" + endl;
        Iterator<Identifier> iterator = identifierMap.values().iterator();
        while (iterator.hasNext()) {
            s += ((Identifier) iterator.next()).toStringPretty() + endl;
        }

        s += "Predicates (" + predicates.size() + "):" + endl;
        for (int i = 0; i < predicates.size(); i++) {
            s += predicates.elementAt(i).toStringPretty() + endl;
        }
        s += "-----------------" + endl;
        return s;

    }

}
