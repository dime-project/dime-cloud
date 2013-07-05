/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

/**
 * Predicate for proving a domain pseudonym.
 */
public class PseudonymPredicate extends Predicate {

    /** Reference to the stored pseudonym. */
    private final String name;

    /**
     * Constructor.
     * 
     * @param theName
     *            String that refers to the pseudonym.
     */
    public PseudonymPredicate(final String theName) {
        super(Predicate.PredicateType.PSEUDONYM);
        name = theName;
    }

    /**
     * @return Human-readable representation of the pseudonym predicate.
     */
    public final String toStringPretty() {
        String s = "PseudonymPredicate(" + name + ")";
        return s;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

}
