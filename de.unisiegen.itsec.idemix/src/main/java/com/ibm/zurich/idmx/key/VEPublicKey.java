/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.key;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Public key for verifiable encryption.
 */
public class VEPublicKey {

    /** Modulus <tt>n</tt>. */
    private final BigInteger n;
    /** Modulus squared <tt>n<sup>2</sup></tt>. */
    private final BigInteger n2;
    /** Generator. */
    private final BigInteger g;
    /** Value <tt>y<sub>1</sub></tt> of the encryption. */
    private final BigInteger y1;
    /** Value <tt>y<sub>2</sub></tt> of the encryption. */
    private final BigInteger y2;
    /** Value <tt>y<sub>3</sub></tt> of the encryption. */
    private final BigInteger y3;

    /** Location of the system parameters which were used to generate the key. */
    private final URI systemParametersLocation;
    /** System parameters (loaded from the above location). */
    private final SystemParameters sp;

    /**
     * Constructor.
     * 
     * @param spLocation
     *            System parameter location.
     * @param theG
     *            Generator.
     * @param theN
     *            Modulus.
     * @param theY1
     *            Value <tt>y<sub>1</sub></tt> of the encryption.
     * @param theY2
     *            Value <tt>y<sub>2</sub></tt> of the encryption.
     * @param theY3
     *            Value <tt>y<sub>3</sub></tt> of the encryption.
     */
    public VEPublicKey(URI spLocation, BigInteger theG, BigInteger theN,
            BigInteger theY1, BigInteger theY2, BigInteger theY3) {
        super();
        systemParametersLocation = spLocation;
        sp = (SystemParameters) StructureStore.getInstance().get(
                systemParametersLocation);

        n = theN;
        n2 = n.pow(2);
        g = theG;
        y1 = theY1;
        y2 = theY2;
        y3 = theY3;
    }

    /**
     * @return System parameters.
     */
    public SystemParameters getSystemParameters() {
        return sp;
    }

    /**
     * @return System parameters location.
     */
    public URI getSystemParametersLocation() {
        return systemParametersLocation;
    }

    /**
     * @return Modulus.
     */
    public final BigInteger getN() {
        return n;
    }

    /**
     * @return Modulus squared.
     */
    public final BigInteger getN2() {
        return n2;
    }

    /**
     * @return Generator.
     */
    public final BigInteger getG() {
        return g;
    }

    /**
     * @return Value <tt>y<sub>1</sub></tt> of the encryption.
     */
    public final BigInteger getY1() {
        return y1;
    }

    /**
     * @return Value <tt>y<sub>2</sub></tt> of the encryption.
     */
    public final BigInteger getY2() {
        return y2;
    }

    /**
     * @return Value <tt>y<sub>3</sub></tt> of the encryption.
     */
    public final BigInteger getY3() {
        return y3;
    }

    /**
     * @return <tt>(1 + n) mod (n<sup>2</sup>)</tt>.
     */
    public final BigInteger getH() {
        return BigInteger.ONE.add(this.n).mod(n2);
    }

    /**
     * Returns a random value such that <tt>r in [n/4]</tt>, which is needed
     * when encrypting.
     * 
     * @return <tt>0 <= r <= n/4</tt>.
     */
    public BigInteger getRandom() {
        return Utils.computeRandomNumber(getN().divide(Utils.FOUR), sp);
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
        VEPublicKey other = (VEPublicKey) obj;
        if (g == null) {
            if (other.g != null) {
                return false;
            }
        } else if (!g.equals(other.g)) {
            return false;
        }
        if (n == null) {
            if (other.n != null) {
                return false;
            }
        } else if (!n.equals(other.n)) {
            return false;
        }
        if (n2 == null) {
            if (other.n2 != null) {
                return false;
            }
        } else if (!n2.equals(other.n2)) {
            return false;
        }
        if (sp == null) {
            if (other.sp != null) {
                return false;
            }
        } else if (!sp.equals(other.sp)) {
            return false;
        }
        if (y1 == null) {
            if (other.y1 != null) {
                return false;
            }
        } else if (!y1.equals(other.y1)) {
            return false;
        }
        if (y2 == null) {
            if (other.y2 != null) {
                return false;
            }
        } else if (!y2.equals(other.y2)) {
            return false;
        }
        if (y3 == null) {
            if (other.y3 != null) {
                return false;
            }
        } else if (!y3.equals(other.y3)) {
            return false;
        }
        return true;
    }
}
