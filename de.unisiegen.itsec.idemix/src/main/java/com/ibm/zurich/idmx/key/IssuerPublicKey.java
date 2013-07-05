/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.key;

import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * The Issuer's public key for the CL-signature scheme. In addition to the key
 * itself, this object also contains the epochLength (which defines intervals
 * when credentials expire), and a unique identifier to identify the key.
 * 
 * @see IssuerPrivateKey
 * @see IssuerKeyPair
 */
public final class IssuerPublicKey  {

    /** Logger. */
    private static Logger log = Logger.getLogger(IssuerPublicKey.class
            .getName());
    
    /** Location of the group parameters corresponding to this key. */
    private final URI groupParametersLocation;

    /** <tt>S</tt> as specified in ... */
    private final BigInteger capS;
    /** <tt>Z</tt> as specified in ... */
    private final BigInteger capZ;
    /** Bases for the messages. */
    private final BigInteger[] capR;
    /** Modulus. */
    private final BigInteger n;
    /** Length of an epoch. */
    private final int epochLength;

    /**
     * Constructor for the issuer public key with epoch length. Creates an
     * IssuerPublicKey from the group parameters and includes the epoch length
     * field in the public key.
     * 
     * @param groupParams
     *            Group parameters.
     * @param privKey
     *            Issuer private key.
     * @param nbrOfAttrs
     *            Maximum number of attributes in a signature.
     * @param theEpochLength
     *            Duration of each epoch [in seconds].
     */
    IssuerPublicKey(final URI groupParams, final IssuerPrivateKey privKey,
            final int nbrOfAttrs, final int theEpochLength) {

        groupParametersLocation = groupParams;
        SystemParameters sp = ((GroupParameters) StructureStore.getInstance()
                .get(groupParametersLocation)).getSystemParams();

        if (privKey == null || nbrOfAttrs < sp.getL_res()) {
            throw new IllegalArgumentException();
        }

        if (theEpochLength < 1) {
            // case when no epoch is used
            log.log(Level.FINE, "No epoch used in issuer public key.");
            epochLength = 0;
        } else {
            epochLength = theEpochLength;
        }

        log.log(Level.INFO, "Generating public key");
        Date start = new Date();

        n = privKey.getN();
        capS = Utils.computeGeneratorQuadraticResidue(privKey.getN(), sp);

        // p'*q'
        final BigInteger productPQprime = privKey.getPPrime().multiply(
                privKey.getQPrime());

        // upper = p'q'-1 - 2
        final BigInteger upper = productPQprime.subtract(BigInteger.ONE)
                .subtract(Utils.TWO);
        // capZ: rand num range [2 .. p'q'-1]. we pick capZ in [0..upper] and
        // then add 2.
        final BigInteger x_Z = Utils.computeRandomNumber(upper, sp).add(
                Utils.TWO);
        capZ = capS.modPow(x_Z, privKey.getN());

        // capR[]
        capR = new BigInteger[nbrOfAttrs];
        for (int i = 0; i < nbrOfAttrs; i++) {
            // pick x_R as rand num in range [2 .. p'q'-1]
            final BigInteger x_R = Utils.computeRandomNumber(upper, sp).add(
                    Utils.TWO);
            capR[i] = capS.modPow(x_R, privKey.getN());
        }

        Date stop = new Date();

        log.log(Level.INFO, "\nIssuePublicKey: start: " + start.toString()
                + " end: " + stop.toString());

    }

    /**
     * Constructor for IPK without epoch length. Creates an IssuerPublicKey from
     * the private key, and includes the epoch length field in the public key.
     * 
     * @param groupParams
     *            Group parameters.
     * @param privKey
     *            Issuer private key.
     * @param nbrOfAttrs
     *            Maximum number of attributes in a signature.
     */
    IssuerPublicKey(final URI groupParams, final IssuerPrivateKey privKey,
            final int nbrOfAttrs) {
        this(groupParams, privKey, nbrOfAttrs, -1);
    }

    /**
     * Constructor.
     * 
     * @param theGroupParameters
     *            Group parameters.
     * @param theCapS
     *            Randomization base.
     * @param theCapZ
     *            <tt>Z</tt>.
     * @param theCapR
     *            Bases for messages.
     * @param theN
     *            Modulus.
     * @param theEpochLength
     *            Length of an epoch.
     */
    public IssuerPublicKey(final URI theGroupParameters,
            final BigInteger theCapS, final BigInteger theCapZ,
            final BigInteger[] theCapR, final BigInteger theN,
            final int theEpochLength) {
        capS = theCapS;
        capZ = theCapZ;
        capR = theCapR;
        n = theN;
        epochLength = theEpochLength;
        groupParametersLocation = theGroupParameters;
    }

    /**
     * @return Group parameters.
     */
    public GroupParameters getGroupParams() {
        return (GroupParameters) StructureStore.getInstance().get(
                groupParametersLocation);
    }

    /**
     * @return Group parameters location.
     */
    public final URI getGroupParamsLocation() {
        return groupParametersLocation;
    }

    /**
     * @return True if this IssuerPublicKey has the epoch length field set.
     */
    public boolean hasEpoch() {
        if (epochLength > 0) {
            return true;
        }

        return false;
    }

    /**
     * @return Epoch length (in seconds) if this public key has the epoch field
     *         set. If not, an {@link IllegalArgumentException} is thrown.
     */
    public int getEpochLength() {
        if (!hasEpoch()) {
            throw new IllegalArgumentException("Requesting epochLength from "
                    + "IssuerPublicKey which dosen't have one.");
        }
        return epochLength;
    }

    /**
     * @return Current epoch. Computes an integer value representing the current
     *         epoch. The current epoch is computed as floor(
     *         currentTime/epochLength), where the currentTime and epochLength
     *         are in seconds.
     */
    public BigInteger computeCurrentEpoch() {
        double localEpochLength = (double) getEpochLength();
        double currentTime = ((double) System.currentTimeMillis()) / 1000.0;
        BigInteger currentEpoch = BigInteger.valueOf((long) Math
                .floor(currentTime / localEpochLength));
        return currentEpoch;
    }

    /**
     * @return Number of attributes which may be signed by this public key. (the
     *         dimension of the message space in the CL signature scheme)
     */
    public int getMaxNbrAttrs() {
        return capR.length;
    }

    /**
     * @return Randomization base <tt>S</tt>.
     */
    public BigInteger getCapS() {
        return capS;
    }

    /**
     * @return Signature element <tt>Z</tt>.
     */
    public BigInteger getCapZ() {
        return capZ;
    }

    /**
     * @return Array of attribute bases <tt>R_i</tt>.
     */
    public BigInteger[] getCapR() {
        return capR;
    }

    /**
     * @return Modulus <tt>n</tt>.
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String endl = System.getProperty("line.separator");
        String s = "Issuer's public key: " + endl;
        s += "\tNumber of bases: " + capR.length + endl;
        s += "\tn, capS, capZ : " + Utils.logBigInt(n) + ", "
                + Utils.logBigInt(capS) + ", " + Utils.logBigInt(capZ) + endl;
        s += "\tR[" + 0 + "..." + (capR.length - 1) + "]: ";
        for (int i = 0; i < capR.length; i++) {
            s += Utils.logBigInt(capR[i]);
            if (i < capR.length - 1) {
                s += ", ";
            }
        }

        return s;
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof IssuerPublicKey)) {
            return false;
        }

        IssuerPublicKey ikp = (IssuerPublicKey) o;
        if (this == ikp) {
            return true;
        }
        return (capS.equals(ikp.capS) && capZ.equals(ikp.capZ)
                && n.equals(ikp.n) && Arrays.equals(capR, ikp.capR));
    }

    @Override
    public int hashCode() {
        int tempHashCode = 0;
        tempHashCode += capS.hashCode();
        tempHashCode += capZ.hashCode();
        tempHashCode += n.hashCode();
        tempHashCode += capR.hashCode();
        return tempHashCode;
    }

}
