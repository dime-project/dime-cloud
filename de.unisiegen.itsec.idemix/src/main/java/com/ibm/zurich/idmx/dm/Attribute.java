/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;

import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.DataType;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Attributes consists of a link to an attribute structure, a value, and
 * possibly a list of prime factors.
 */
public class Attribute {

    /** Attribute's structure. */
    private final AttributeStructure structure;
    /** Value of the attribute. */
    private Object value;
    /** Prime encoded attributes list all prime factors that build their value. */
    private final HashSet<String> primeFactors;

    /**
     * Constructor.
     * 
     * @param attStruct
     *            Structure of the attribute.
     * @param theValue
     *            Value of the attribute (might be a
     *            <code>CommitmentOpening</code> or simply a
     *            <code>BigInteger</code>.
     */
    public Attribute(final AttributeStructure attStruct, final Object theValue) {
        super();
        structure = attStruct;
        primeFactors = null;
        value = theValue;
        validateAttribute();
    }

    /**
     * Constructor for prime encoded attributes that are issued in committed
     * issuance mode.
     * 
     * @param attStruct
     *            Structure of the attribute.
     * @param theValue
     *            Value of the attribute (might be a
     *            <code>CommitmentOpening</code> or simply a
     *            <code>BigInteger</code>.
     * @param thePrimeFactors
     *            Names of the prime encoded element values.
     */
    public Attribute(final AttributeStructure attStruct, final Object theValue,
            final HashSet<String> thePrimeFactors) {
        super();
        structure = attStruct;
        primeFactors = thePrimeFactors;
        value = theValue;
        validatePrimeEncodedAttribute();
    }

    /**
     * Validation of normal attributes.
     */
    private void validateAttribute() {
        // Prime encoded attributes have a specific constructor!
        if (getDataType() == DataType.ENUM) {
            throw (new RuntimeException("Wrong constructor for attribute "
                    + structure.getName()));
        }
        // Verify that epoch attributes are of issuance mode known.
        if (getDataType() == DataType.EPOCH
                && getIssuanceMode() != IssuanceMode.KNOWN) {
            throw (new IllegalArgumentException("Epoch attribute must be"
                    + " known attribute."));
        }
    }

    /**
     * Validation of prime encoded attributes.
     */
    private void validatePrimeEncodedAttribute() {
        // Non-prime encoded attributes have a specific constructor!
        if (getDataType() != DataType.ENUM) {
            throw (new RuntimeException("Wrong constructor for attribute "
                    + getName()));
        }
        // Verify the given value with the product computed from the attribute
        // structure list.
        BigInteger tempValue;
        if (value instanceof CommitmentOpening) {
            tempValue = ((CommitmentOpening) value).getMessageValue();
        } else {
            tempValue = (BigInteger) value;
        }
        if (!tempValue.equals(Values.getPrimeEncodedProduct(structure,
                primeFactors))) {
            throw (new RuntimeException("Value of commitment and credential "
                    + "do not correspond."));
        }
    }

    /**
     * @return Attribute structure.
     */
    public final AttributeStructure getStructure() {
        return structure;
    }

    /**
     * @return Index of this attribute w.r.t. the bases in the public key.
     */
    public final int getKeyIndex() {
        return structure.getKeyIndex();
    }

    /**
     * @return Data type of this attribute.
     */
    public final DataType getDataType() {
        return structure.getDataType();
    }

    /**
     * Get the name of this attribute.
     * 
     * @return The name of this attribute.
     */
    public final String getName() {
        return structure.getName();
    }

    /**
     * @return Issuance mode of this attribute.
     */
    public final IssuanceMode getIssuanceMode() {
        return structure.getIssuanceMode();
    }

    /**
     * @return Attribute value. For committed attributes, we return the original
     *         message value.
     */
    public final BigInteger getValue() {
        if (structure.getIssuanceMode() == IssuanceMode.COMMITTED) {
            if (value instanceof CommitmentOpening) {
                return ((CommitmentOpening) value).getMessageValue();
            } else {
                throw (new RuntimeException("Message of committed value "
                        + "cannot be retrieved."));
            }
        } else {
            return (BigInteger) value;
        }
    }

    /**
     * @return Whole attribute value object.
     */
    public final Object getValueObject() {
        return value;
    }

    /**
     * Set the value of this attribute. Needed for updating attributes for
     * credentials having epochs.
     * 
     * @param theValue
     *            The value of the attribute.
     */
    public final void setValue(final BigInteger theValue) {
        value = theValue;
    }

    /**
     * Set the object value of this attribute.
     * 
     * @param theValue
     *            The value object of the attribute.
     */
    public final void setValueObject(final Object theValue) {
        value = theValue;
    }

    /**
     * @return Prime factors.
     */
    public final HashSet<String> getPrimeFactors() {
        return primeFactors;
    }

    /**
     * @return Human-readable description of this attribute, in the form
     *         <code>(name: keyIndex: value: dataType)</code>.
     */
    public final String toStringPretty() {
        Object val = getValue();
        if (val == null) {
            val = "null";
        } else if (val instanceof CommitmentOpening) {
            val = ((CommitmentOpening) val).toStringPretty();
        } else {
            val = Utils.logBigInt((BigInteger) val);
        }
        if (getDataType() == DataType.ENUM) {
            String listOfPrimes = " [";
            Iterator<String> iterator = primeFactors.iterator();
            while (iterator.hasNext()) {
                listOfPrimes += " "
                        + Utils.logBigInt(structure.getPrimeFactor(iterator
                                .next()));
            }
            val = ((String) val).concat(listOfPrimes + "]");
        }

        String s = "( " + getName() + ": " + getKeyIndex() + ": "
                + getDataType().toString() + ": " + val + ")";
        return s;
    }

}
