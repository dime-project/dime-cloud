/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.key;

/**
 * Key pair object for verifiable encryption.
 */
public final class VEKeyPair {

    /** Private key of the key pair. */
    private final VEPrivateKey vePrivateKey;
    /** Public key of the key pair. */
    private final VEPublicKey vePublicKey;

    /**
     * Constructor.
     */
    private VEKeyPair() {
        vePrivateKey = new VEPrivateKey(null, null);
        vePublicKey = vePrivateKey.getPublicKey();
    }

    /**
     * @return the privKey
     */
    public synchronized final VEPrivateKey getPrivKey() {
        return vePrivateKey;
    }

    /**
     * @return the pubKey
     */
    public synchronized final VEPublicKey getPubKey() {
        return vePublicKey;
    }
}
