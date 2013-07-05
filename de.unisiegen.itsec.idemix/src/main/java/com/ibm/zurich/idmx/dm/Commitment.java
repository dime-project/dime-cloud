/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Class to express a Commitment to one or more messages. Commitments have the
 * form <tt>C = Z<sup>m</sup> * S<sup>r</sup> mod n</tt>, or the multi-base
 * variant, which commits to <tt>L</tt> messages:
 * <tt>C = R<sub>0</sub><sup>m_0</sup> * ... * 
 * R<sub>L</sub><sup>m_L</sup> * S<sup>r</sup> mod n</tt>. We store the values
 * of <tt>Z</tt>, <tt>S</tt>, <tt>n</tt> and <tt>c</tt>. This class does not
 * store the opening info of the commitment (i.e. the exponents).
 * 
 * @see CommitmentOpening
 */
public class Commitment implements Serializable {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /** Value of the commitment. */
    protected final BigInteger val;
    /**
     * <tt>S</tt> is the base used for the randomizing factor (i.e.,
     * <tt>S<sup>r</sup></tt>.
     */
    protected final BigInteger capS;
    /**
     * Bases used to commit to messages: <tt>R<sub>0</sub></tt>,
     * <tt>R<sub>1</sub></tt>, ... <tt>R<sub>L</sub></tt>.
     */
    protected final Vector<BigInteger> bases;
    /** Modulus. */
    protected final BigInteger n;

    /** Convenience: Number of bases (counted from <code>bases</code>). */
    protected final int numBases;

    /**
     * Single message commitment constructor using a given commitment value and
     * the issuer public key to retrieve the bases.
     * 
     * @param value
     *            Value of the commitment, i.e. the product
     *            <tt>(R<sub>0</sub><sup>m</sup>)*(S<sup>r</sup>)
     *            mod n</tt>.
     * @param ipk
     *            Issuer public key containing <tt>R<sub>0</sub></tt>,
     *            <tt>S</tt>, and <tt>n</tt>.
     */
    public Commitment(final BigInteger value, final IssuerPublicKey ipk) {
        if (value == null) {
            throw new IllegalArgumentException();
        }
        capS = ipk.getCapS();
        n = ipk.getN();
        val = value;
        numBases = 1;
        bases = new Vector<BigInteger>();
        bases.add(ipk.getCapR()[0]);
    }

    /**
     * Single message commitment constructor using a given bases.
     * 
     * @param value
     *            Value of the commitment, i.e. the product
     *            <tt>(R<sub>0</sub><sup>m</sup>)*(S<sup>r</sup>)
     *            mod n</tt>.
     * @param capR_0
     *            Base for the message.
     * @param theCapS
     *            Base for the randomizing factor.
     * @param theN
     *            Modulus.
     */
    public Commitment(final BigInteger value, final BigInteger capR_0,
            final BigInteger theCapS, final BigInteger theN) {
        if (value == null) {
            throw new IllegalArgumentException();
        }
        capS = theCapS;
        n = theN;
        val = value;
        numBases = 1;
        bases = new Vector<BigInteger>();
        bases.add(capR_0);
    }

    /**
     * Multi-base commitment constructor.
     * 
     * @param value
     *            Commitment value <tt>R<sub>0</sub><sup>m_0</sup> * ... * 
     *            R<sub>L</sub><sup>m_L</sup> * S<sup>r</sup> mod n</tt>.
     * @param ipk
     *            Issuer's public key (used to retrieve the bases).
     * @param theNumBases
     *            the number of messages committed
     */
    public Commitment(final BigInteger value, final IssuerPublicKey ipk,
            int theNumBases) {
        if (theNumBases < 1 || theNumBases > ipk.getMaxNbrAttrs()) {
            throw new IllegalArgumentException("Invalid number of bases "
                    + "requested in commitment constructor.");
        }
        val = value;
        numBases = theNumBases;
        capS = ipk.getCapS();
        n = ipk.getN();

        bases = new Vector<BigInteger>(theNumBases);
        for (int i = 0; i < theNumBases; i++) {
            bases.add(ipk.getCapR()[i]);
        }
    }

    /**
     * Multibase constructor.
     * 
     * @param value
     *            the value of the commitment, i.e. the product
     *            (R_0^m)*...*(R_L^m_L)*(S^r) mod n.
     * @param theBases
     *            a vector of the bases R_0, ..., R_L
     * @param theCapS
     *            the base for the randomizer
     * @param theN
     *            the modulus
     * 
     */
    public Commitment(final BigInteger value,
            final Vector<BigInteger> theBases, final BigInteger theCapS,
            final BigInteger theN) {
        capS = theCapS;
        bases = theBases;
        numBases = theBases.size();
        n = theN;
        val = value;
    }

    /**
     * @return First message base (called <tt>R</tt> in single-base or
     *         <tt>R<sub>0</sub></tt> in multi-base commitments).
     */
    public final BigInteger getCapR() {
        return bases.get(0);
    }

    /**
     * @return Randomization base (i.e., <tt>S</tt>).
     */
    public final BigInteger getCapS() {
        return capS;
    }

    /**
     * @return Modulus <tt>n</tt>.
     */
    public final BigInteger getN() {
        return n;
    }

    /**
     * @return Number of bases.
     */
    public final int getNumBases() {
        return numBases;
    }

    /**
     * @return Committed value (i.e. the computed commitment, not the opening
     *         information).
     */
    public final BigInteger getCommitment() {
        return val;
    }

    /**
     * Persist commitment to some file.
     * 
     * @param fn
     *            File name.
     * @return True if serialization was successful.
     */
    public boolean save(final String fn) {
        return Serializer.serialize(fn, this);
    }

    /**
     * @param fn
     *            File name.
     * @return Commitment loaded from file.
     */
    public static Commitment load(final String fn) {
        return (Commitment) Serializer.deserialize(fn, Commitment.class);
    }

    /**
     * @param i
     *            Index of the base that should be retrieved.
     * @return The i-th base in the commitment (R_i). Does not include the
     *         randomizing base (S).
     */
    public final BigInteger getMsgBase(final int i) {
        if (i >= numBases || i < 0) {
            throw new IllegalArgumentException("Invalid index (" + i
                    + ") in Commitment::getMsgBase");
        }
        return bases.get(i);
    }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String s = "";
        s += "Commitment : ";
        s += "R = (" + Utils.logVector(bases) + ") ";
        s += "S = " + Utils.logBigInt(capS) + " ";
        s += "val = " + Utils.logBigInt(val) + " ";
        return s;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        Commitment other = (Commitment) obj;
        if (capS == null) {
            if (other.capS != null) {
                return false;
            }
        } else if (!capS.equals(other.capS)) {
            return false;
        }
        if (bases == null) {
            if (other.bases != null) {
                return false;
            }
        } else if (!bases.equals(other.bases)) {
            return false;
        }
        if (n == null) {
            if (other.n != null) {
                return false;
            }
        } else if (!n.equals(other.n)) {
            return false;
        }
        if (numBases != other.numBases) {
            return false;
        }
        if (val == null) {
            if (other.val != null) {
                return false;
            }
        } else if (!val.equals(other.val)) {
            return false;
        }
        return true;
    }

}
