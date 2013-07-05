/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.util.HashSet;

/**
 * Object that contains the value of an attribute during the issuance process.
 * All the information is handed over to an attribute once a valid signature is
 * retrieved.
 */
public class Value {

    /** Contents of this value (CommitmentOpening or BigInteger). */
    private final Object value;
    /** HashSet of all the elements that this value encodes. */
    private final HashSet<String> primeEncodedElements;

    /**
     * Constructor.
     * 
     * @param theValue
     *            Contents of this value (CommitmentOpening or BigInteger).
     * @param thePrimeEncodedElements
     *            HashSet of all the elements that this value encodes.
     */
    protected Value(final Object theValue,
            final HashSet<String> thePrimeEncodedElements) {
        value = theValue;
        primeEncodedElements = thePrimeEncodedElements;
    }

    /**
     * @return Value (either a CommitmentOpening or a BigInteger).
     */
    public final Object getContent() {
        return value;
    }

    /**
     * @return HashSet indicating all the elements that this prime encoding
     *         encodes.
     */
    public final HashSet<String> getPrimeEncodedElements() {
        return primeEncodedElements;
    }
}
