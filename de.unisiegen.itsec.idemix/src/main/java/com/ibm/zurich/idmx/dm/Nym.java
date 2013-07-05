/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Pseudonym abstraction. Must be serializable as it's also to be persisted.
 */
public class Nym implements Serializable {

    /** Logger. */
    private static Logger log = Logger.getLogger(Nym.class.getName());
    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /** Group parameters. */
    private final GroupParameters gp;

    /** Value of the nym: <tt>g^m1 h^r</tt>. */
    private final BigInteger nym;
    /** Randomness of nym <tt>r</tt>. */
    private final BigInteger random;
    /** Name of this nym. */
    private final String name;

    /**
     * Constructor. Randomness is generated on the fly.
     * 
     * @param groupParams
     *            Group parameters.
     * @param m
     *            Message value.
     * @param theName
     *            Name of the nym.
     */
    public Nym(final GroupParameters groupParams, final BigInteger m,
            final String theName) {
        super();
        gp = groupParams;
        final BigInteger theRandom = Utils.computeRandomNumber(BigInteger.ONE,
                groupParams.getRho(), groupParams.getSystemParams());
        if (BigInteger.ONE.compareTo(theRandom) > 0
                || gp.getRho().compareTo(theRandom) < 0) {
            throw new IllegalArgumentException("r outside [1..\rho]");
        }
        random = theRandom;
        nym = Utils.computeCommitment(gp, m, random);
        name = theName;
        log.log(Level.FINE, " Message of the nym:    " + Utils.logBigInt(m));
        log.log(Level.FINE, " Randomness of the nym: "
                + Utils.logBigInt(random));
        log.log(Level.FINE, " G of the nym:          "
                + Utils.logBigInt(gp.getG()));
        log.log(Level.FINE, " H of the nym:          "
                + Utils.logBigInt(gp.getH()));
        log.log(Level.FINE, " Modulus of the nym:    "
                + Utils.logBigInt(gp.getCapGamma()));
    }

    /**
     * @return Name of the pseudonym.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Random value that blinds the message.
     */
    public final BigInteger getRandom() {
        return random;
    }

    /**
     * @return Pseudonym <tt>g^m1 h^r</tt>.
     */
    public final BigInteger getNym() {
        return nym;
    }
   
    /**
     * Persist nym to some file.
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
     * @return Pseudonym loaded from the given file.
     */
    public static Nym load(final String fn) {
        return (Nym) Serializer.deserialize(fn, Nym.class);
    }

}
