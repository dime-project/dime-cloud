/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

/**
 * Abstract class to inherited by the various predicate types.
 */
public abstract class Predicate {

    /**
     * Defines the different predicates.
     */
    public enum PredicateType {
        /** Camenisch-Lysyanskaya Predicate (proof of knowledge). */
        CL,
        /** Commitment predicate. */
        COMMITMENT,
        /** Domain pseudonym predicate. */
        DOMAINNYM,
        /** Pseudonym predicate. */
        PSEUDONYM,
        /** Verifiable encryption predicate. */
        VERENC,
        /** Inequality predicate. */
        INEQUALITY,
        /** Epoch predicate. */
        EPOCH,
        /** Representation predicate. */
        REPRESENTATION,
        /** Message predicate. */
        MESSAGE,
        /** Prime encoding predicate. */
        ENUMERATION
    };

    /** PredicateType of this predicate. **/
    private final PredicateType predicateType;

    /**
     * Constructor.
     * 
     * @param thePredicateType
     *            Type of the predicate.
     */
    public Predicate(final PredicateType thePredicateType) {
        predicateType = thePredicateType;
    }

    /**
     * Returns the predicateType of the predicate.
     * 
     * @return PredicateType of the predicate.
     */
    public final PredicateType getPredicateType() {
        return predicateType;
    }

    /**
     * @return Human-readable description of the predicate.
     */
    public abstract String toStringPretty();
}
