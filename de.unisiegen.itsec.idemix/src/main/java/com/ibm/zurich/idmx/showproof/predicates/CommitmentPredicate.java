/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

import java.util.Vector;

import com.ibm.zurich.idmx.showproof.Identifier;

/**
 * This predicate expresses proofs about external commitments that use the bases
 * from the issuer public key under which the proof is created.
 */
public class CommitmentPredicate extends Predicate {

    /** Name of the commitment object this predicate refers to. */
    private String name;
    /** Identifiers referring to the exponents of this commitment. */
    private Vector<Identifier> identifiers;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the commitment object this predicate refers to.
     * @param theIdentifiers
     *            Identifiers referring to the exponents of this commitment.
     */
    public CommitmentPredicate(final String theName,
            final Vector<Identifier> theIdentifiers) {
        super(PredicateType.COMMITMENT);

        identifiers = theIdentifiers;
        name = theName;
    }

    /**
     * @return Name of the commitment object this predicate refers to.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Identifiers referring to the exponents of this commitment.
     */
    public final Vector<Identifier> getIdentifiers() {
        return identifiers;
    }

    /**
     * @return Human-readable string of this predicate.
     */
    public final String toStringPretty() {
        String s = "CommitmentPredicate(" + name + ", "
                + Identifier.idsToString(identifiers) + ")";
        return s;
    }
}
