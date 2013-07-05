/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.utils;

import java.math.BigInteger;
import java.net.URI;
import java.util.Date;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Idemix group parameters abstraction.
 */
public class GroupParameters {

    /** Logger. */
    private static Logger log = Logger.getLogger(GroupParameters.class
            .getName());

    /**
     * System parameters with respect to which the group parameters have been
     * created.
     */
    private final URI systemParametersLocation;
    /** Committment group order. */
    private final BigInteger capGamma;
    /** Order of the subgroup of the commitment group. */
    private final BigInteger rho;
    /** Generator. */
    private final BigInteger g;
    /** Generator. */
    private final BigInteger h;

    /**
     * Constructor.
     * 
     * @param theCapGamma
     *            Modulus of the commitment group.
     * @param theRho
     *            Order of the subgroup of the commitment group.
     * @param theG
     *            Generator of ...
     * @param theH
     *            Generator of ...
     * @param theSp
     *            System parameter location.
     */
    GroupParameters(final BigInteger theCapGamma, final BigInteger theRho,
            final BigInteger theG, final BigInteger theH, final URI theSp) {
        super();
        capGamma = theCapGamma;
        rho = theRho;
        g = theG;
        h = theH;
        systemParametersLocation = theSp;
    }

    /**
     * @return System parameters.
     */
    public final SystemParameters getSystemParams() {
        return (SystemParameters) StructureStore.getInstance().get(
                systemParametersLocation);
    }

    /**
     * @return System parameters location.
     */
    public final URI getSystemParamsLocation() {
        return systemParametersLocation;
    }

    /**
     * @return the gamma
     */
    public BigInteger getCapGamma() {
        return capGamma;
    }

    /**
     * @return the rho
     */
    public BigInteger getRho() {
        return rho;
    }

    /**
     * @return the g
     */
    public BigInteger getG() {
        return g;
    }

    /**
     * @return the h
     */
    public BigInteger getH() {
        return h;
    }

    /**
     * @return The number of elements in the group parameters.
     */
    public final int getNumber() {
        // FIXME (pbi) this should count the number of elements of the group
        // parameters.
        return 4;
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof GroupParameters)) {
            return false;
        }

        GroupParameters otherGp = (GroupParameters) o;
        if (this == otherGp) {
            return true;
        }
        return (systemParametersLocation
                .equals(otherGp.systemParametersLocation)
                && g.equals(otherGp.g)
                && h.equals(otherGp.h)
                && capGamma.equals(otherGp.capGamma) && rho.equals(otherGp.rho));
    }

    /**
     * Generates group parameters according to section 4.1 in math doc.
     * 
     * @param systemParameterLocation
     *            Location of the system parameters.
     * @return newly created group parameters.
     */
    public static GroupParameters generateGroupParams(
            final URI systemParameterLocation) {

        Date start = new Date();

        final SystemParameters sp = (SystemParameters) StructureStore
                .getInstance().get(systemParameterLocation);

        BigInteger capGamma;
        BigInteger g;
        BigInteger rho;
        BigInteger h;

        int l_rho = sp.getL_rho();
        int l_b = sp.getL_Gamma() - l_rho;

        // select rho of given length with prime probability.
        do {
            rho = new BigInteger(l_rho, sp.getL_pt(),
                    Utils.getRandomGenerator());
        } while (!Utils.isInInterval(rho, l_rho - 1, l_rho));

        // find the group order Gamma.
        BigInteger b; // co-factor of (Gamma - 1).
        do {
            // see Table 4 of math doc as well as section 4.1
            do {
                b = new BigInteger(l_b, Utils.getRandomGenerator());
                // b != 0 (mod rho)
            } while (b.mod(rho).equals(BigInteger.ZERO));

            // Gamma = (rho * b) + 1
            capGamma = rho.multiply(b).add(BigInteger.ONE);

        } while (!capGamma.isProbablePrime(sp.getL_pt())
                || !Utils.isInInterval(capGamma, sp.getL_Gamma() - 1,
                        sp.getL_Gamma()));

        // get generator g. see math doc for this detail.
        BigInteger gPrime;
        do {
            gPrime = Utils.computeRandomNumber(capGamma, sp);
            g = gPrime.modPow(b, capGamma);
        } while (g.equals(BigInteger.ONE));
        // g'^{b} != 1 (mod Gamma)

        // compute second generator h = g^random.
        final BigInteger rh = Utils.computeRandomNumber(BigInteger.ZERO, rho,
                sp);

        h = g.modPow(rh, capGamma);

        Date stop = new Date();

        log.log(Level.INFO, "Param generation: start: " + start.toString()
                + " end: " + stop.toString());

        return new GroupParameters(capGamma, rho, g, h, systemParameterLocation);
    }
}
