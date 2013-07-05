/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.key;

import java.net.URI;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;

/**
 * The issuer's key pair for the CL-signature scheme. Contains the public and
 * private portions as separate objects, and includes a keyUUID to uninquely
 * identify this key.
 * 
 * @see IssuerPrivateKey
 * @see IssuerPublicKey
 */
public class IssuerKeyPair {

    /** Private key of the issuer. */
    private final IssuerPrivateKey privateKey;
    /** Public key of the issuer. */
    private final IssuerPublicKey publicKey;

    /**
     * @return Private portion of the key pair.
     */
    public final IssuerPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @return Public portion of the key pair.
     */
    public final IssuerPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Constructor.
     * 
     * @param groupParams
     *            Group parameters for which the key is to be created.
     * @param maxNbrOfAttrs
     *            Number of attributes an issuer key supports (i.e., number of
     *            bases excluding the reserved attributes such as the master
     *            secret).
     * @param epochLength
     */
    public IssuerKeyPair(final URI publicKeyLocation, final URI groupParams,
            int maxNbrOfAttrs, final int epochLength) {
        super();
        SystemParameters sp = ((GroupParameters) StructureStore.getInstance()
                .get(groupParams)).getSystemParams();
        privateKey = new IssuerPrivateKey(sp);
        privateKey.publicKeyLocation = publicKeyLocation;
        maxNbrOfAttrs += sp.getL_res();
        publicKey = new IssuerPublicKey(groupParams, privateKey, maxNbrOfAttrs,
                epochLength);
    }

    /**
     * Constructor. Uses a persistent object at an indicated location to create
     * the java object.
     * 
     * @param issuerPrivateKey
     *            Private Key.
     */
    public IssuerKeyPair(final IssuerPrivateKey issuerPrivateKey) {
        privateKey = issuerPrivateKey;
        publicKey = privateKey.getPublicKey();
    }

    // /**
    // * Creates a cache of pre-computed values (based on this public key) to
    // * allow faster computation. Does nothing if Constants.USE_FAST_EXPO_CACHE
    // * is not set.
    // */
    // private boolean cacheKeyBases() {
    //
    // if (!Constants.USE_FAST_EXPO_CACHE) {
    // return false;
    // }
    //
    // SystemParameters sp = publicKey.getGroupParams().getSystemParams();
    //
    // int maxExpWidth = sp.getL_v() + sp.getL_Phi() + sp.getL_H();
    // if (!ModPowCache.register(publicKey.getCapS(), publicKey.getN(),
    // maxExpWidth)) {
    // return false;
    // }
    //
    // maxExpWidth = sp.getL_n() + sp.getL_Phi();
    // if (!ModPowCache.register(this.publicKey.getCapZ(),
    // this.publicKey.getN(), maxExpWidth)) {
    // return false;
    // }
    //
    // final BigInteger[] capR = this.publicKey.getCapR();
    // maxExpWidth = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
    // for (int i = 0; i < capR.length; i++) {
    // if (!ModPowCache.register(capR[i], this.publicKey.getN(),
    // maxExpWidth)) {
    // return false;
    // }
    // }
    //
    // return true;
    // }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof IssuerKeyPair)) {
            return false;
        }

        IssuerKeyPair ikp = (IssuerKeyPair) o;
        return (privateKey.equals(ikp.privateKey) && publicKey
                .equals(ikp.publicKey));
    }

    @Override
    public final int hashCode() {
        int tmp = privateKey.hashCode();
        tmp += publicKey.hashCode();
        return tmp;
    }

}
