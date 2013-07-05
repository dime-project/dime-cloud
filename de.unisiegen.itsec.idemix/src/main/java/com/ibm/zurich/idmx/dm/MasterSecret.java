/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * The user's master secret. It's a big-integer with minor functionality that
 * serves as call-out possibility if a smart card is used to store the master
 * secret.
 */
public class MasterSecret {

    /** Group parameters location. */
    private final URI groupParametersLocation;
    /** Group parameters. */
    private GroupParameters groupParameters;
    /** Master secret key. */
    private final BigInteger value;
    /** List of all nyms that the user generated using this master secret. */
    private final HashMap<String, Nym> nymList;
    /** Randomness for the master secret. */
    private BigInteger mTilde_1 = null;
    /** Commitment for a nyms. */
    private final HashMap<String, Nym> nymTildeList;
    /** Domain pseudonym. */
    private final HashMap<String, DomNym> domNymList;
    /** Commitment for the domain pseudonym. */
    private final HashMap<String, DomNym> domNymTildeList;

    /** Challenge use during a proof. */
    private BigInteger challenge;

    /**
     * Convenience Constructor. Creates a new master secret.
     * 
     * @param groupParamsLocation
     *            Location of the group parameters.
     */
    public MasterSecret(final URI groupParamsLocation) {
        this(null, groupParamsLocation, null, null);
    }

    /**
     * Constructor. Creates a master secret with the given values.
     * 
     * @param theValue
     *            Value of the master secret.
     * @param groupParamsLocation
     *            Location of the group parameters.
     * @param theNymList
     *            List of pseudonyms generated.
     * @param theDomNymList
     *            List of domain pseudonyms (may be useful when providing
     *            information whether the user has already visited a domain).
     */
    public MasterSecret(final BigInteger theValue,
            final URI groupParamsLocation,
            final HashMap<String, Nym> theNymList,
            final HashMap<String, DomNym> theDomNymList) {

        groupParametersLocation = groupParamsLocation;
        groupParameters = (GroupParameters) StructureStore.getInstance().get(
                groupParametersLocation);

        if (theValue == null) {
            value = Utils.computeRandomNumber(groupParameters.getSystemParams()
                    .getL_m());
        } else {
            value = theValue;
        }

        if (theNymList == null) {
            nymList = new HashMap<String, Nym>();
        } else {
            nymList = theNymList;
        }
        nymTildeList = new HashMap<String, Nym>();
        if (theDomNymList == null) {
            domNymList = new HashMap<String, DomNym>();
        } else {
            domNymList = theDomNymList;
        }
        domNymTildeList = new HashMap<String, DomNym>();

        initProof();
    }

    /**
     * Initiate a new proof by choosing a new random value to blind the master
     * secret.
     */
    public final void initProof() {
        SystemParameters sp = groupParameters.getSystemParams();
        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;
        mTilde_1 = Utils.computeRandomNumberSymmetric(bitlength);
    }

    /**
     * @param product
     *            Value that will be multiplied.
     * @return <tt>product * R<sup>m_1</sup> (mod n)</tt>
     */
    public final BigInteger getCapU(final BigInteger product,
            final BigInteger capR, final BigInteger n) {

        return Utils.expMul(product, capR, value, n);

    }

    /**
     * @param product
     *            Value that will be multiplied.
     * @return T-value <tt>product * R<sup>mTilde_1</sup> (mod n)</tt>.
     */
    public final BigInteger getCapUTilde(final BigInteger product,
            final BigInteger capR, final BigInteger n) {

        if (mTilde_1 == null) {
            initProof();
        }
        return Utils.expMul(product, capR, mTilde_1, n);

    }

    /**
     * @param theChallenge
     *            Challenge.
     * @return S-value of the master secret.
     */
    public final BigInteger getMHat(final BigInteger theChallenge) {
        BigInteger mHat_1 = null;
        challenge = theChallenge;

        mHat_1 = Utils.computeResponse(mTilde_1, theChallenge, value);

        return mHat_1;
    }

    /**
     * @param name
     *            Name of the pseudonym.
     * @return Value of the pseudonym with the given name.
     */
    public final BigInteger loadNym(final String name) {
        BigInteger nymValue = null;
        if (nymList.get(name) == null) {
            Nym nym = new Nym(groupParameters, value, name);
            nymList.put(name, nym);
            nymValue = nym.getNym();
        } else {
            nymValue = nymList.get(name).getNym();
        }
        return nymValue;
    }

    // /**
    // * Saves a pseudonym with the given name to the provided file name.
    // *
    // * @param name
    // * Name of the pseudonym.
    // * @param filename
    // * File name.
    // * @return True if pseudonym was successfully saved.
    // */
    // public final void saveNym(final String name, final URI filename) {
    // XMLSerializer.getInstance().serialize(nymList.get(name), filename);
    // }

    // /**
    // * @return T-value of the pseudonym.
    // */
    // public final BigInteger getNymTilde() {
    // nymTilde = new Nym(issuerPublicKey.getGroupParams(), mTilde_1, " ");
    // return nymTilde.getNym();
    // }

    /**
     * @return T-value of the pseudonym.
     * @param nymName
     *            Name of the pseudonym.
     */
    public final BigInteger getNymTilde(final String nymName) {
        // TODO (pbi): remove 'name' field in nyms
        Nym nymTilde = new Nym(groupParameters, mTilde_1, " ");
        nymTildeList.put(nymName, nymTilde);
        return nymTilde.getNym();
    }

    /**
     * @param nymName
     *            Name of the pseudonym.
     * @return S-value of the pseudonym with the given name.
     */
    public final BigInteger getRHat(final String nymName) {
        Nym nym = nymList.get(nymName);
        assert (nym != null);
        // TODO (frp): step 2.1 in ProvePseudonym
        BigInteger rHat = Utils.computeResponse(nymTildeList.get(nymName)
                .getRandom(), challenge, nym.getRandom());
        // TODO (frp): spec says that rHat is to compute in Z, it does not say
        // in Z_rho.
        // rHat = rHat.mod(issuerPublicKey.getGroupParams().getRho());
        return rHat;
    }

    /**
     * @param domain
     *            Domain string value.
     * @return Domain pseudonym computed on the basis of the given domain.
     */
    public final DomNym loadDomNym(final String domain) {
        DomNym domNym = domNymList.get(domain);
        if (domNym == null) {
            BigInteger g_dom = DomNym.computeG_dom(groupParameters, domain);
            BigInteger nym = Utils.expMul(null, g_dom, value,
                    groupParameters.getCapGamma());
            domNym = new DomNym(groupParameters, nym, g_dom);
            domNymList.put(domain, domNym);
        }
        return domNym;
    }

    // /**
    // * @param theDomNym
    // * Domain pseudonym that is added to this master secret.
    // */
    // public final void loadDomNym(final DomNym theDomNym) {
    // domNym = theDomNym;
    // }

    /**
     * @return T-Value of the domain pseudonym.
     */
    public final DomNym getDomNymTilde(final String domain) {
        DomNym domNym = domNymList.get(domain);
        if (domNym == null) {
            return null;
        }
        DomNym domNymTilde = domNymTildeList.get(domain);
        if (domNymTilde == null) {
            BigInteger nym = Utils.expMul(null, domNym.getG_dom(), mTilde_1,
                    groupParameters.getCapGamma());
            domNymTilde = new DomNym(groupParameters, nym, domNym.getG_dom());
            domNymTildeList.put(domain, domNymTilde);
        }
        return domNymTilde;
    }

    /**
     * Serialization method.
     * 
     * @return Value of the Master Secret.
     */
    public final BigInteger getValue() {
        return value;
    }

    /**
     * Serialization method.
     * 
     * @return Location of the group parameters.
     */
    public final URI getGroupParametersLocation() {
        return groupParametersLocation;
    }

    /**
     * Serialization method.
     * 
     * @return List of pseudonyms.
     */
    public final HashMap<String, Nym> getNymList() {
        return nymList;
    }

    /**
     * Serialization method.
     * 
     * @return List of domain pseudonyms.
     */
    public final HashMap<String, DomNym> getDomNymList() {
        return domNymList;
    }
}
