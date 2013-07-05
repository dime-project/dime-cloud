/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.dm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * This class is a sub-class of Commitment. We store the opening information
 * consisting of the message value(s) <code>m</code> and the random value
 * <code>r</code> used to compute the commitment's value. The commitment value
 * is stored in the super-class along with the bases and modulus.
 * 
 * @see Commitment
 */
public class CommitmentOpening extends Commitment implements Serializable {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;
    /** Logger. */
    private transient Logger log = Logger.getLogger(this.getClass().getName());

    /** The value(s) of the message(s) we're committing to. */
    private Vector<BigInteger> msgs;
    /** The random value r. */
    private BigInteger rand;

    /**
     * Constructor.
     * 
     * @param message
     *            Message value (i.e., commitment exponent).
     * @param random
     *            Random value.
     * @param capR_0
     *            Base for the message.
     * @param capS
     *            Randomization base.
     * @param modulus
     *            Modulus.
     * @param l_n
     *            Bit length of the modulus.
     */
    public CommitmentOpening(final BigInteger capR_0, final BigInteger message,
            final BigInteger capS, final BigInteger random,
            final BigInteger modulus, final int l_n) {
        super(genVal(capR_0, capS, modulus, message, random), capR_0, capS,
                modulus);
        msgs = new Vector<BigInteger>();
        msgs.add(message);
        // rand = genRandom(modulus, l_n);
        rand = random;
    }

    /**
     * Constructor.
     * 
     * @param message
     *            Message value.
     * @param random
     *            Random value.
     * @param issuerPublicKey
     *            Issuer public key used to retrieve bases and modulus (i.e.,
     *            <tt>Z</tt>, <tt>S</tt> and <tt>n</tt>).
     */
    public CommitmentOpening(final BigInteger message, final BigInteger random,
            final IssuerPublicKey issuerPublicKey) {
        super(genVal(issuerPublicKey.getCapR()[0], issuerPublicKey.getCapS(),
                issuerPublicKey.getN(), message, random), issuerPublicKey);
        msgs = new Vector<BigInteger>();
        msgs.add(message);
        rand = random;
    }

    /**
     * Multi-base commitment opening constructor, which creates a single
     * commitment to many messages.
     * 
     * @param messages
     *            Value of the messages (i.e., the commitment exponents).
     * @param random
     *            Random value.
     * @param issuerPublicKey
     *            Issuer public key used to retrieve bases and modulus (i.e.,
     *            <tt>Z</tt>, <tt>S</tt> and <tt>n</tt>).
     */
    public CommitmentOpening(final Vector<BigInteger> messages,
            final BigInteger random, final IssuerPublicKey issuerPublicKey) {
        super(genVal(issuerPublicKey, messages, random), issuerPublicKey,
                messages.size());
        msgs = messages;
        rand = random;
    }

    /**
     * Constructor used for loading commitment opening from XML.
     * 
     * @param value
     *            Commitment value.
     * @param bases
     *            Message bases.
     * @param capS
     *            Randomization base.
     * @param n
     *            Commitment modulus.
     * @param messages
     *            Message values (commitment exponents).
     * @param random
     *            Random value.
     */
    public CommitmentOpening(final BigInteger value,
            final Vector<BigInteger> bases, final BigInteger capS,
            final BigInteger n, final Vector<BigInteger> messages,
            final BigInteger random) {
        super(value, bases, capS, n);

        msgs = messages;
        rand = random;
    }

    /**
     * @return Message value of the commitment.
     */
    public final BigInteger getMessageValue() {
        assert (numBases == 1 && msgs.size() == 1);
        return msgs.elementAt(0);
    }

    /**
     * @return Random value of the commitment.
     */
    public final BigInteger getRandom() {
        return rand;
    }

    /**
     * Sets the message value for a single-base commitment.
     * 
     * @param value
     *            message value.
     */
    public final void setMessageValue(final BigInteger value) {
        assert (numBases == 1 && msgs.size() == 1);
        msgs.set(0, value);
    }

    /**
     * Persist commitment to some file.
     * 
     * @param fn
     *            File name.
     * @return True if serialization is successful.
     */
    public final boolean save(final String fn) {
        return Serializer.serialize(fn, this);
    }

    /**
     * @param fn
     *            File name.
     * @return Commitment opening loaded from file.
     */
    public static CommitmentOpening load(final String fn) {
        return (CommitmentOpening) Serializer.deserialize(fn,
                CommitmentOpening.class);
    }

    /**
     * @return Commitment object. Once a prover has setup the CommitmentOpening,
     *         he can create a Commitment in order to send to the verifier.
     */
    public final Commitment getCommitmentObject() {
        return new Commitment(val, bases, capS, n);
    }

    /**
     * @param i
     *            Index of the message that will be retrieved.
     * @return Message at position <code>i</code> in the commitment.
     */
    public final BigInteger getMessage(final int i) {
        if (i < 0 || i > numBases - 1) {
            throw new IllegalArgumentException("Invalid message index (" + i
                    + ") requested in CommitmentOpening::getMessage");
        }
        return msgs.get(i);
    }

    /**
     * @return Human-readable description of this object
     */
    public final String toStringPretty() {
        String s = "";
        s += super.toStringPretty();
        s += "m = (" + Utils.logVector(msgs) + ") ";
        s += "r = " + Utils.logBigInt(rand) + " ";

        return s;
    }

    /**
     * Verify if the generated value in the commitment object is correct to
     * ensure the prover and verifier have the same commitment (only useful for
     * debugging).
     * 
     * @return True if re-computed commitment equals the stored commitment.
     */
    public final boolean verifyCommitment() {
        Commitment co = this.getCommitmentObject();
        BigInteger C = co.getCommitment();
        log.log(Level.INFO, "Stored commitment value: " + Utils.logBigInt(C));

        BigInteger product = null;
        for (int i = 0; i < bases.size(); i++) {
            product = Utils.expMul(product, bases.get(i), msgs.get(i), n);
        }
        product = Utils.expMul(product, capS, rand, n);

        log.log(Level.INFO,
                "Computed commitment value: " + Utils.logBigInt(product));

        return (product.equals(C));
    }

    /**
     * Computes the value of the commitment (for a single message).
     * 
     * @param capR_0
     *            First message base.
     * @param capS
     *            Randomization base.
     * @param modulus
     *            Modulus.
     * @param message
     *            Message (i.e., the exponent).
     * @param random
     *            Random exponent.
     * @return <tt>Z<sup>m</sup> * S<sup>r</sup> mod n</tt>.
     */
    private static BigInteger genVal(final BigInteger capR_0,
            final BigInteger capS, final BigInteger modulus,
            final BigInteger message, final BigInteger random) {
        BigInteger res = null;
        res = Utils.expMul(res, capR_0, message, modulus);
        res = Utils.expMul(res, capS, random, modulus);
        return res;
    }

    /**
     * Computes the committed value for a multi-base commitment (based on the
     * bases and modulus of the given public key).
     * 
     * @param issuerPublicKey
     *            Issuer public key (used to retrieve bases and modulus).
     * @param messages
     *            Messages (i.e., the exponents).
     * @param random
     *            Random exponent.
     * @return <tt>R<sub>0</sub><sup>m_0</sup>*...*<tt>R<sub>L</sub><sup>m_L</sup> 
     *         * S<sup>r</sup> mod n</tt>.
     */
    private static BigInteger genVal(final IssuerPublicKey issuerPublicKey,
            final Vector<BigInteger> messages, final BigInteger random) {
        BigInteger n = issuerPublicKey.getN();
        Vector<Exponentiation> product = new Vector<Exponentiation>();
        for (int i = 0; i < messages.size(); i++) {
            Exponentiation e = new Exponentiation(issuerPublicKey.getCapR()[i],
                    messages.get(i), n);
            product.add(e);
        }
        product.add(new Exponentiation(issuerPublicKey.getCapS(), random, n));
        return Utils.multiExpMul(product, n);
    }

    /**
     * To get a random value specifically for commitment computations. We can't
     * squirrel this into the constructors since we need to put the random value
     * into a final private field. Hence the client must explicitly pass the
     * random value generated with this method.
     * 
     * @param n
     *            RSA modulus.
     * @param l_n
     *            Bit length of the modulus.
     * @return random value.
     */
    public static BigInteger genRandom(final BigInteger n, final int l_n) {
        final BigInteger upperBound = n.divide(Utils.FOUR);

        BigInteger r;
        do {
            r = Utils.computeRandomNumber(l_n - 1);
        } while (r.compareTo(BigInteger.ZERO) < 0
                || r.compareTo(upperBound) > 0);

        return r;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        CommitmentOpening other = (CommitmentOpening) obj;
        if (msgs == null) {
            if (other.msgs != null) {
                return false;
            }
        } else if (!msgs.equals(other.msgs)) {
            return false;
        }
        if (rand == null) {
            if (other.rand != null) {
                return false;
            }
        } else if (!rand.equals(other.rand)) {
            return false;
        }
        return true;
    }
}
