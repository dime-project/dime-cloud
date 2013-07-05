/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.ve;

import java.math.BigInteger;
import java.net.URI;
import java.util.Vector;

import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Verifiable encryption of a plaintext for a given public key.
 */
public class VerifiableEncryption {

    /** Location of the verifiable encryption public key. */
    private final URI vePublicKeyLocation;
    /** Convenience: Verifiable encryption public key. */
    private final VEPublicKey vePk;

    /** The label used in the encryption. */
    protected final BigInteger capL;
    /** Value <tt>u</tt> of the ciphertext. */
    protected final BigInteger u;
    /** Value <tt>e</tt> of the ciphertext. */
    protected final BigInteger e;
    /** Value <tt>v</tt> of the ciphertext. */
    protected final BigInteger v;

    /**
     * Load en existing encryption.
     * 
     * @param theU
     *            Value <tt>u</tt> of the ciphertext.
     * @param theE
     *            Value <tt>e</tt> of the ciphertext.
     * @param theV
     *            Value <tt>v</tt> of the ciphertext.
     * @param theCapL
     *            Parameter <tt>L</tt> (label) of the ciphertext.
     */
    public VerifiableEncryption(URI theVEPublicKeyLocation, BigInteger theU,
            BigInteger theE, BigInteger theV, BigInteger theCapL) {
        vePublicKeyLocation = theVEPublicKeyLocation;
        vePk = (VEPublicKey) StructureStore.getInstance().get(
                vePublicKeyLocation);
        u = theU;
        v = theV;
        e = theE;
        capL = theCapL;
    }

    /**
     * Method to encrypt the message <tt>m</tt> under the public key <tt>pk</tt>
     * with label <tt>L</tt> and randomness <tt>r</tt>. The method
     * PublicKey.getRandom() generates random values in the correct interval
     * (0...n/4).
     * 
     * @param m
     *            Message.
     * @param r
     *            Randomness.
     * @param theVEPublicKeyLocation
     *            Location of the verifiable encryption public key.
     * @param theCapL
     *            Label.
     */
    public VerifiableEncryption(final BigInteger m, final BigInteger r,
            final URI theVEPublicKeyLocation, final Object theCapL) {
        super();

        vePublicKeyLocation = theVEPublicKeyLocation;
        vePk = (VEPublicKey) StructureStore.getInstance().get(
                vePublicKeyLocation);

        if (theCapL instanceof String) {
            capL = Utils.hashString((String) theCapL, vePk
                    .getSystemParameters().getL_H());
        } else if (theCapL instanceof BigInteger) {
            capL = (BigInteger) theCapL;
        } else {
            throw new IllegalArgumentException("[VerifiableEncryption:"
                    + "Constructor] Label must be a String or a "
                    + "BigInteger.");
        }

        if (m.compareTo(vePk.getN()) > 0) {
            throw new IllegalArgumentException("Message of the verifiable "
                    + "encryption is larger than the modulus of the provided "
                    + "key.");
        }
        if (!Utils.isInInterval(r, BigInteger.ZERO,
                vePk.getN().divide(Utils.FOUR))) {
            throw new IllegalArgumentException("Randomness provided to "
                    + "encryption is not in the correct interval [0, n/4]");
        }

        // u = g^r
        BigInteger n2 = vePk.getN2();
        u = Utils.modPow(vePk.getG(), r, n2);
        e = computeE(vePk, r, m);
        v = abs(computeY2Y3(vePk, u, e, capL, r), n2);
    }

    /**
     * Returns the keyed hash function of the verifiable encryption where the
     * key is chosen randomly from an appropriate key space associated with the
     * security parameter.
     * 
     * @return Hash of the verifiable encryption.
     */
    public BigInteger getHash() {
        return VerifiableEncryption.computeHash(vePk.getSystemParameters().getL_H(), u,
                e, capL);
    }

    /**
     * @return Location of the verifiable encryption public key.
     */
    public URI getVEPublicKeyLocation() {
        return vePublicKeyLocation;
    }

    /**
     * @return Label of the encryption.
     */
    public BigInteger getCapL() {
        return capL;
    }

    /**
     * @return Parameter <tt>u</tt> of the encryption.
     */
    public synchronized final BigInteger getU() {
        return u;
    }

    /**
     * @return Parameter <tt>e</tt> of the encryption.
     */
    public synchronized final BigInteger getE() {
        return e;
    }

    /**
     * @return Parameter <tt>v</tt> of the encryption.
     */
    public synchronized final BigInteger getV() {
        return v;
    }

    /**
     * @return Verifiable encryption public key.
     */
    public VEPublicKey getPK() {
        return vePk;
    }

    /**
     * Computes <tt>abs(a,n<sup>2</sup>)</tt>.
     * 
     * @param a
     *            Parameter to determine absolute value.
     * @param n2
     *            <tt>n<sup>2</sup></tt>.
     * @return <tt>a mod n<sup>2</sup></tt> if <tt>a <= n<sup>2</sup>/2</tt>,
     *         else <tt>(n<sup>2</sup> - a) mod n<sup>2</sup></tt>.
     */
    public static BigInteger abs(final BigInteger a, final BigInteger n2) {
        // if (!(BigInteger.ZERO.compareTo(a) < 0 && a.compareTo(n2) < 0)) {
        // throw new IllegalArgumentException("out of range");
        // }
        final BigInteger n2Half = n2.shiftRight(1);
        if (a.compareTo(n2Half) > 0) {
            return (n2.subtract(a).mod(n2));
        } else {
            return a.mod(n2);
        }
    }

    /**
     * Computes <tt>(y2*y3^H(u,e,L))^r</tt>.
     * 
     * @param pk
     *            Public key to be encrypted for.
     * @param u
     *            Parameter <tt>u</tt> of the ciphertext.
     * @param e
     *            Parameter <tt>e</tt> of the ciphertext.
     * @param capL
     *            Parameter <tt>L</tt> (label) of the ciphertext.
     * @param r
     *            Randomness.
     * @return <tt>(y2*y3^H(u,e,L))^r</tt>.
     */
    final public static BigInteger computeY2Y3(final VEPublicKey pk,
            final BigInteger u, final BigInteger e, final BigInteger capL,
            final BigInteger r) {

        final BigInteger n2 = pk.getN2();

        final BigInteger hash = computeHash(pk.getSystemParameters().getL_H(),
                u, e, capL);
        final BigInteger y3_hash = Utils.modPow(pk.getY3(), hash, n2);
        final BigInteger y2y3 = Utils.modPow(pk.getY2().multiply(y3_hash), r,
                n2);
        // return y2y3;
        return abs(y2y3, n2);
    }

    /**
     * Computes the keyed hash function of the verifiable encryption where the
     * key is chosen randomly from an appropriate key space associated with the
     * security parameter.
     * 
     * @param l_H
     *            Bit length of the hash.
     * @param u
     *            First parameter to be hashed, when used in the verifiable
     *            encryption context, this is the paramter <tt>u</tt> from the
     *            encryption.
     * @param e
     *            Second parameter to be hashed, when used in the verifiable
     *            encryption context, this is paramter <tt>e</tt>.
     * @param capL
     *            Third parameter to be hashed, when used in the verifiable
     *            encryption context, this is the label of the encryption.
     */
    public static BigInteger computeHash(int l_H, BigInteger u, BigInteger e,
            BigInteger capL) {
        // TODO (pbi): this is not a keyed hash function as in the paper. why?
        final BigInteger[] arr = new BigInteger[3];
        arr[0] = u;
        arr[1] = e;
        arr[2] = capL;
        return Utils.hashOf(l_H, arr);
    }

    /**
     * To compute <tt>y1^r * h^m mod n<sup>2</sup></tt>.
     * 
     * @param pk
     *            Public key.
     * @param r
     *            Randomness.
     * @param m
     *            Message.
     * @return <tt>y1^r * h^m mod n<sup>2</sup></tt>.
     */
    public static final BigInteger computeE(final VEPublicKey pk,
            final BigInteger r, final BigInteger m) {
        final BigInteger h = pk.getH();
        final Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(pk.getY1(), r, pk.getN2()));
        expos.add(new Exponentiation(h, m, pk.getN2()));
        // e = y1^r * h^m
        return Utils.multiExpMul(expos, pk.getN2());
    }

    // /**
    // * Persist encryption to some file.
    // *
    // * @param fn
    // * File name.
    // * @return True if serialization is successful.
    // */
    // public boolean save(final String fn) {
    // return Serializer.serialize(fn, this);
    // }
    //
    // /**
    // * @param fn
    // * File name.
    // * @return verifiable encryption loaded from the given file.
    // */
    // public static Encryption load(final String fn) {
    // final Encryption dn = (Encryption) Serializer.deserialize(fn,
    // Encryption.class);
    // return dn;
    // }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String s = "Encryption " + " (u = " + Utils.logBigInt(u) + ", e = "
                + Utils.logBigInt(e) + " v = " + Utils.logBigInt(v) + ", L = "
                + Utils.logBigInt(capL);
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
        VerifiableEncryption other = (VerifiableEncryption) obj;
        if (capL == null) {
            if (other.capL != null) {
                return false;
            }
        } else if (!capL.equals(other.capL)) {
            return false;
        }
        if (e == null) {
            if (other.e != null) {
                return false;
            }
        } else if (!e.equals(other.e)) {
            return false;
        }
        if (u == null) {
            if (other.u != null) {
                return false;
            }
        } else if (!u.equals(other.u)) {
            return false;
        }
        if (v == null) {
            if (other.v != null) {
                return false;
            }
        } else if (!v.equals(other.v)) {
            return false;
        }
        return true;
    }

}
