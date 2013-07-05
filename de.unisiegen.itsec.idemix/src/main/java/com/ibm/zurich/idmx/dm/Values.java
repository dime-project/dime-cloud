/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;

import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Object that contains a list of values. This list is needed during the
 * issuance process, when the attributes are not yet created.
 */
public class Values {

    /** List of all the values used during issuance. */
    private final Hashtable<String, Value> values;
    /** System parameters (used for the length of the hash). */
    private final SystemParameters sp;

    /**
     * Constructor.
     * 
     * @param sysParam
     *            System parameters.
     */
    public Values(final SystemParameters sysParam) {
        sp = sysParam;
        values = new Hashtable<String, Value>();
    }

    /**
     * Adds a value to its list.
     * 
     * @param name
     *            Name of the attribute this element corresponds to.
     * @param value
     *            Value of the attribute this element corresponds to.
     */
    public final void add(final String name, final Object value) {
        Object encodedValue;
        if (value instanceof String) {
            encodedValue = Utils.encode(sp.getL_H(), (String) value);
        } else {
            encodedValue = value;
        }
        add(name, encodedValue, null);
    }

    /**
     * Adds a value to the list of values.
     * 
     * @param name
     *            Name of the attribute this element corresponds to.
     * @param value
     *            Value of the attribute this element corresponds to.
     * @param primeEncodedElements
     *            List of encodings the attribute contains.
     */
    public final void add(final String name, final Object value,
            final HashSet<String> primeEncodedElements) {
        values.put(name, new Value(value, primeEncodedElements));
    }

    // /**
    // * Adds a value to its list.
    // *
    // * @param name
    // * Name of the attribute this element corresponds to.
    // * @param value
    // * Value of the attribute this element corresponds to.
    // * @param l_H
    // * Bit length of the hash.
    // * @param primeEncodedElements
    // * List of encodings the attribute contains.
    // */
    // private void add(final String name, Object value, final int l_H,
    // final HashSet<String> primeEncodedElements) {
    // if (value instanceof String) {
    // value = encode((String) value, l_H);
    // }
    // values.put(name, new Value(value, primeEncodedElements));
    // }
    //
    // /**
    // * @param value
    // * String to be encoded into a BigInteger.
    // * @param l_H
    // * Length of the hash.
    // * @return BigInteger encoding the given string.
    // * @deprecated this should be done when adding the values to the
    // credential.
    // * at that point the correspondence between data type and value
    // * can be checked.
    // */
    // private BigInteger encode(final String value, final int l_H) {
    // return Utils.hashString(value, l_H);
    // }

    /**
     * @param name
     *            Name of the value to be retrieved.
     * @return Value object corresponding to the given name.
     */
    public final Value get(final String name) {
        return values.get(name);
    }

    /**
     * @return Iterator of the key set of the values.
     */
    public final Iterator<String> iterator() {
        return values.keySet().iterator();
    }

    /**
     * @param attStructure
     *            Structure of the attribute.
     * @return Content of the value.
     */
    public final Object getValue(final AttributeStructure attStructure) {
        Value value = values.get(attStructure.getName());
        if (attStructure.getIssuanceMode() != IssuanceMode.COMMITTED) {
            return (BigInteger) value.getContent();
        } else {
            return ((CommitmentOpening) value.getContent()).getMessageValue();
        }
    }

    /**
     * Calculates the value using a list of encodings.
     * 
     * @param attStructure
     *            Structure of the attribute (from here the list encodings is
     *            retrieved).
     * @param primeEncodingElements
     *            List of elements encoded in the attribute.
     * @return Product of primes corresponding to the elements indicated in the
     *         <tt>primeEncodingElements</tt> list.
     */
    public static BigInteger getPrimeEncodedProduct(
            final AttributeStructure attStructure,
            final HashSet<String> primeEncodingElements) {
        Iterator<String> iterator = primeEncodingElements.iterator();
        BigInteger value = BigInteger.ONE;
        while (iterator.hasNext()) {
            value = value
                    .multiply(attStructure.getPrimeFactor(iterator.next()));
        }
        return value;
    }

    public final boolean containsKey(String name) {
        return values.containsKey(name);
    }
}
