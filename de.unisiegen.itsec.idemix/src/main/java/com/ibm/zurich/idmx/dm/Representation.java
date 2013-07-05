/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Class to express a Representation of the form
 * <tt>R := g_1^x_1 * ... * g_k^x_k mod Y</tt> where <tt>Y</tt> may be a
 * composite or prime integer; proof is that knowledge of the representation
 * holds modulo <tt>Y</tt>.
 * 
 * This class stores the modulus, the bases, the computed value <tt>R</tt>, and
 * optionally the group order. The prover holds the exponents in a
 * RepresentationOpening object.
 * 
 * @see RepresentationOpening
 */
public class Representation implements Serializable {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /** The value of the representation R. */
    private final BigInteger val;
    /** Bases <tt>g_1, ..., g_k</tt>. **/
    protected final Vector<BigInteger> bases;
    /** Modulus. */
    private final BigInteger modulus;
    /** Name to refer to this Representation. **/
    private final String name;

    /**
     * Representation constructor.
     * 
     * @param value
     *            Computed value <tt>R = g_1^x_1 * ... * g_k^x_k mod Y</tt>.
     * @param theBases
     *            Bases <tt>g_1, ... , g_k</tt>.
     * @param theModulus
     *            Modulus <tt>Y</tt>.
     * @param theName
     *            Name of this representation.
     */
    public Representation(final BigInteger value,
            final Vector<BigInteger> theBases, final BigInteger theModulus,
            final String theName) {
        if (theBases.size() < 1) {
            throw new IllegalArgumentException("Invalid number of bases "
                    + "in Representation constructor.");
        }
        if (theName == null) {
            throw new IllegalArgumentException("You must provide a name"
                    + " for the Representation.");
        }

        val = value;
        name = theName;
        bases = theBases;
        modulus = theModulus;
    }

    /**
     * @return Representation <tt>R</tt>.
     */
    public final BigInteger getRepresentation() {
        return val;
    }

    /**
     * @return Name of this representation.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Modulus of this representation.
     */
    public final BigInteger getModulus() {
        return modulus;
    }

    /**
     * @param i
     *            Index of the base that should be retrieved.
     * @return The i-th base of the representation.
     */
    public final BigInteger getBase(final int i) {
        if (i >= bases.size() || i < 0) {
            throw new IllegalArgumentException("Invalid index (" + i
                    + ") in Representation::getBase");
        }
        return bases.get(i);
    }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String s = "";
        s += "Representation " + name + " : ";
        s += "bases = (" + Utils.logVector(bases) + ") ";
        s += "val R = " + Utils.logBigInt(val) + " ";
        s += "modulus = " + Utils.logBigInt(modulus) + " ";
        return s;
    }

    /**
     * Persist Representation to given file.
     * 
     * @param fn
     *            File name.
     * @return True if serialization was successful.
     */
    public boolean save(final String fn) {
        return Serializer.serialize(fn, this);
    }

    /**
     * To fetch a Representation from file.
     * 
     * @param fn
     *            File name.
     * @return commitment.
     */
    public static Representation load(final String fn) {
        return (Representation) Serializer
                .deserialize(fn, Representation.class);
    }
}
