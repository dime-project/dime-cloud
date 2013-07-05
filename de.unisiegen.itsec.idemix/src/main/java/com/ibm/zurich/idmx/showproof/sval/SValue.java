/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.sval;

/**
 * Object that stores an s-value.
 */
public class SValue {

    /** Content of the s-value. */
    private Object value;

    /**
     * Constructor.
     * 
     * @param theValue
     *            S-Value.
     */
    public SValue(final Object theValue) {
        value = theValue;
    }

    /**
     * @return S-value.
     */
    public final Object getValue() {
        return value;
    }
}
