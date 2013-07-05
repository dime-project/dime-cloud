/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * This class is a sub-class of Represenation. We store the opening information
 * consisting of the exponent value(s) used to compute the commitment's value.
 * The commitment value is stored in the super-class along with the bases and
 * modulus.
 * 
 * @see Representation
 */
public class RepresentationOpening extends Representation {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /** The value(s) of the message(s) we're committing to. */
    private Vector<BigInteger> exponents;

    /**
     * Constructor. Note vector bases and exponents must have the same lengths.
     * 
     * @param bases
     *            Bases <tt>g_1, ... g_k</tt>.
     * @param theExponents
     *            Exponents.
     * @param modulus
     *            Modulus.
     * @param name
     *            Name of the representation.
     */
    public RepresentationOpening(final Vector<BigInteger> bases,
            final Vector<BigInteger> theExponents, final BigInteger modulus,
            final String name) {
        super(genVal(bases, theExponents, modulus), bases, modulus, name);
        exponents = theExponents;
    }

    /**
     * @return Representation object. Once a prover has setup the
     *         RepresentationOpening, he can create a Representation in order to
     *         send to the verifier.
     */
    public final Representation getRepresentationObject() {
        return new Representation(getRepresentation(), bases, getModulus(),
                getName());
    }

    /**
     * @param i
     *            Index of the exponent that should be retrieved.
     * @return The i-th exponent of the representation.
     */
    public final BigInteger getExponent(final int i) {
        if (i < 0 || i > bases.size() - 1) {
            throw new IllegalArgumentException("Invalid message index (" + i
                    + ") requested in RepresentationOpening::getMessage");
        }
        return exponents.get(i);
    }

    /**
     * @return Human-readable description of this object.
     */
    public final String toStringPretty() {
        String s = "";
        s += super.toStringPretty();
        s += "exponents = (" + Utils.logVector(exponents) + ") ";
        return s;
    }

    /**
     * Persist RepresentationOpening to file.
     * 
     * @param fn
     *            File name.
     * @return True if serialization was successful.
     */
    public final boolean save(final String fn) {
        return Serializer.serialize(fn, this);
    }

    /**
     * @param fn
     *            File name.
     * @return RepresentationOpening from file.
     */
    public static RepresentationOpening load(final String fn) {
        RepresentationOpening c = (RepresentationOpening) Serializer
                .deserialize(fn, RepresentationOpening.class);
        return c;
    }

    /**
     * @param bases
     *            Bases of the representation.
     * @param exponents
     *            Exponents of the representation.
     * @param modulus
     *            Modulus of the representation.
     * @return Computed representation value <tt>R</tt>.
     */
    private static BigInteger genVal(final Vector<BigInteger> bases,
            final Vector<BigInteger> exponents, final BigInteger modulus) {
        if (exponents.size() != bases.size()) {
            throw new IllegalArgumentException("Number of bases and "
                    + "exponents must be the same");
        }
        Vector<Exponentiation> product = new Vector<Exponentiation>();
        for (int i = 0; i < bases.size(); i++) {
            Exponentiation e = new Exponentiation(bases.get(i), exponents
                    .get(i), modulus);
            product.add(e);
        }
        return Utils.multiExpMul(product, modulus);
    }
}
