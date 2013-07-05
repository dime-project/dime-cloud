/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

/**
 * This predicate proves knowledge of a domain pseudonym. The base is computed
 * from the given domain and as exponent we use the master secret.
 */
public final class DomainNymPredicate extends Predicate {

    /** Name of the domain (used for the creation of the base). */
    private String domain;

    /**
     * Constructor.
     * 
     * @param theDomain
     *            String representing the domain.
     */
    public DomainNymPredicate(final String theDomain) {
        super(PredicateType.DOMAINNYM);
        if (theDomain == null) {
            throw new IllegalArgumentException("Domain not specified.");
        }
        domain = theDomain;
    }

    /**
     * @return Name of the domain.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String s = "DomainNymPredicate( " + domain + " )";
        return s;
    }

}
