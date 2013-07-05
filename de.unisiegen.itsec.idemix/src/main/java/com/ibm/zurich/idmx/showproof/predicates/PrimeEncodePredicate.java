/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.Vector;

import com.ibm.zurich.idmx.showproof.Identifier;

/**
 * This predicate expresses proofs on prime encoded attributes. It takes an
 * identifier <code>identifier</code>, a list of attribute names (which allow
 * for retrieval of the corresponding primes) and an operator
 * <code>operator</code>, to describe the proof that
 * <code>identifier operator attributes/constants</code> holds. The operator may
 * be one of {AND, NOT, OR}, specified by the <code>PrimeEncodeOp</code> in this
 * class.
 */
public class PrimeEncodePredicate extends Predicate {

    /**
     * Operators for prime encoded attributes.
     */
    public enum PrimeEncodeOp {
        /**
         * Allows showing that a prime encoded attribute contains one or several
         * values. It requires the attribute and a constant that consists of the
         * multiplication of the elements that need to be proved as input.
         */
        AND,

        /**
         * Allows showing that a prime encoded attribute does NOT contain one or
         * several values. It requires the attribute and a constant that
         * consists of the multiplication of the elements that need to be proved
         * as input.
         */
        NOT,

        /**
         * Allows showing that a prime encoded attribute contains one among
         * several values. It requires the attribute and a constant that
         * consists of the multiplication of all the elements that the user
         * might possess.
         */
        OR
    };

    /** Name to refer to this prime encoding predicate. */
    private final String name;
    /** Identifier for the prime encoded value. */
    private final Identifier identifier;
    /** Vector of primes that are compared to the attribute. */
    private Vector<BigInteger> constants;
    /** Vector of attributes (those values are needed to get the primes). */
    private final Vector<String> attributes;
    /** Operator used for the comparison. */
    private final PrimeEncodeOp operator;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name to refer to this prime encoding predicate.
     * @param theIdentifier
     *            Identifier for the prime encoded value.
     * @param theAttributes
     *            Vector of attributes (those values are needed to get the
     *            primes).
     * @param theOperator
     *            Operator used for the comparison.
     */
    public PrimeEncodePredicate(final String theName,
            final Identifier theIdentifier, final Vector<String> theAttributes,
            final PrimeEncodeOp theOperator) {
        super(PredicateType.ENUMERATION);

        identifier = theIdentifier;
        attributes = theAttributes;
        name = theName;
        operator = theOperator;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Identifier associated to this prime encoded value.
     */
    public final Identifier getIdentifier() {
        return identifier;
    }

    /**
     * @return Operator of the prime encoding.
     */
    public final PrimeEncodeOp getOperator() {
        return operator;
    }

    /**
     * @return Constants compared to the attribute (via the identifier).
     */
    public final Vector<BigInteger> getConstants() {
        return constants;
    }

    /**
     * Sets the constants using the attribute structures.
     * 
     * @param theConstants
     *            Constants (primes) that should be compared to the attribute
     *            identifier.
     */
    public final void setConstants(final Vector<BigInteger> theConstants) {
        constants = theConstants;
    }

    /**
     * @return Names of the attributes, which allow for retrieval of the
     *         corresponding prime factors.
     */
    public final Vector<String> getAttributeNames() {
        return attributes;
    }

    /**
     * @param atts
     *            Add names of attributes, which will allow for retrieval of the
     *            corresponding prime factors.
     */
    public final void addAttributeNames(final Vector<String> atts) {
        attributes.addAll(atts);
    }

    /**
     * @return Human-readable string of the predicate.
     */
    public final String toStringPretty() {
        String string = "PrimeEncodePredicate(" + name + ", "
                + identifier.getName() + ", (";

        if (attributes != null) {
            Iterator<String> iterator = attributes.iterator();
            while (iterator.hasNext()) {
                string = string.concat(iterator.next() + ", ");
            }
        }
        if (constants != null) {
            Iterator<BigInteger> iterator = constants.iterator();
            while (iterator.hasNext()) {
                string = string.concat(iterator.next() + ", ");
            }
        }
        return string.concat(operator + ")");
    }
}
