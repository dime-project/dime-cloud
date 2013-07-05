/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.key;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.ModPowCache;

/**
 * Private key of a trusted party offering verifiable encryption on its behalf.
 */
public class VEPrivateKey {

    /** Location of the public key. */
    private final URI vePublicKeyLocation;
    /** Convenience: Verifiable encryption public key. */
    private final VEPublicKey vePublicKey;
    /** Order of modulus <tt>n</tt>. */
    private final BigInteger orderN;
    /** Value <tt>x<sub>1</sub></tt> of the encryption. */
    private final BigInteger x1;
    /** Value <tt>x<sub>2</sub></tt> of the encryption. */
    private final BigInteger x2;
    /** Value <tt>x<sub>3</sub></tt> of the encryption. */
    private final BigInteger x3;

    /** Convenience: System parameters (retrieved using the public key). */
    private final SystemParameters sp;

    /**
     * Constructor.
     * 
     * @param theVEPublicKeyLocation
     *            Location of the verifiable encryption public key.
     */
    public VEPrivateKey(final URI theSystemParametersLocation,
            final URI theVEPublicKeyLocation) {

        vePublicKeyLocation = theVEPublicKeyLocation;
        sp = (SystemParameters) StructureStore.getInstance().get(
                theSystemParametersLocation);

        final Npq npq = IssuerPrivateKey.getNPQ(sp.getL_n(), sp.getL_pt());

        if (!checkK(npq, sp.getL_enc())) {
            throw new RuntimeException("security param k too large");
        }
        BigInteger n = npq.getN();

        orderN = getGroupOrder(npq);
        BigInteger n2 = (n.multiply(n));
        final BigInteger n2div4 = n2.shiftRight(2);

        x1 = Utils.computeRandomNumber(n2div4, sp);
        x2 = Utils.computeRandomNumber(n2div4, sp);
        x3 = Utils.computeRandomNumber(n2div4, sp);

        final BigInteger gPrime = chooseGPrime(n2, sp);
        BigInteger g = Utils.modPow(gPrime, n.multiply(Utils.TWO), n2);

        BigInteger y1 = Utils.modPow(g, x1, n2);
        BigInteger y2 = Utils.modPow(g, x2, n2);
        BigInteger y3 = Utils.modPow(g, x3, n2);

        vePublicKey = new VEPublicKey(theSystemParametersLocation, g, n, y1,
                y2, y3);

        if (Constants.USE_FAST_EXPO_CACHE) {
            ModPowCache.register(g, n2, n2.bitLength());
        }
    }

    /**
     * Constructor. Used to create object from serialized version.
     * 
     * @param thePublicKeyLocation
     *            Location of the verifiable encryption public key.
     * @param _orderN
     * @param _x1
     * @param _x2
     * @param _x3
     */
    public VEPrivateKey(URI thePublicKeyLocation, BigInteger _orderN,
            BigInteger _x1, BigInteger _x2, BigInteger _x3) {
        vePublicKeyLocation = thePublicKeyLocation;
        vePublicKey = (VEPublicKey) StructureStore.getInstance().get(
                vePublicKeyLocation);
        sp = vePublicKey.getSystemParameters();

        orderN = _orderN;
        x1 = _x1;
        x2 = _x2;
        x3 = _x3;
    }

    public BigInteger getOrderN() {
        return orderN;
    }

    /**
     * @return the n
     */
    public final BigInteger getN() {
        return vePublicKey.getN();
    }

    public final BigInteger getN2() {
        return vePublicKey.getN2();
    }

    /**
     * @return the x1
     */
    public final BigInteger getX1() {
        return x1;
    }

    /**
     * @return the x2
     */
    public final BigInteger getX2() {
        return x2;
    }

    /**
     * @return the x3
     */
    public final BigInteger getX3() {
        return x3;
    }

    /**
     * @return the g
     */
    public final BigInteger getG() {
        return vePublicKey.getG();
    }

    /**
     * @return Public key corresponding to this private key.
     */
    public final VEPublicKey getPublicKey() {
        return vePublicKey;
    }

    /**
     * @return Location of the public key.
     */
    public final URI getPublicKeyLocation() {
        return vePublicKeyLocation;
    }

    private BigInteger chooseGPrime(final BigInteger n2, SystemParameters sp) {
        BigInteger gPrime = null;
        do {
            gPrime = Utils.computeRandomNumber(n2, sp);
            // 0 <= gPrime <= n2
            // to be in cyclic group Z_n2 we must make sure there is an inverse
            // there is an inverse if gcd( g', n2) == 1.
        } while (!gPrime.gcd(n2).equals(BigInteger.ONE));
        return gPrime;
    }

    /**
     * To test the condition on 2^k < min( p, q, p'*q')
     * 
     * @param npq
     * @param k
     * @return success/failure.
     */
    private static boolean checkK(final Npq npq, int k) {
        final BigInteger q = npq.getQ();
        final BigInteger p = npq.getP();

        final BigInteger twoK = BigInteger.ONE.shiftLeft(k);
        if (twoK.compareTo(p) >= 0) {
            return false;
        }
        if (twoK.compareTo(q) >= 0) {
            return false;
        }
        // p' = (p-1)/2, q' = (q-1)/2
        final BigInteger pPrime_qPrime = ((p.subtract(BigInteger.ONE))
                .shiftRight(1)).multiply((q.subtract(BigInteger.ONE))
                .shiftRight(1));
        if (twoK.compareTo(pPrime_qPrime) >= 0) {
            return false;
        }
        return true;
    }

    /**
     * Compute group order of Z_n^*. n = pq, p prime, q prime => order is
     * (p-1)(q-1)
     * 
     * @param npq
     * @return group order.
     */
    private static BigInteger getGroupOrder(final Npq npq) {
        final BigInteger q = npq.getQ();
        final BigInteger p = npq.getP();
        return q.subtract(BigInteger.ONE).multiply(p.subtract(BigInteger.ONE));
    }

}
