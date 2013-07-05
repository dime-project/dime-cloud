/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.credsystem.utils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.issuance.update.UpdateSpecification;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPrivateKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.Parser;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.XMLSerializer;

/**
 *
 */
public class Locations {

    /** Logger. */
    private static Logger log = Logger.getLogger(Locations.class.getName());

    private static String SYSTEM_PARAMETER_NAME = "sp.xml";
    public static String GROUP_PARAMETER_NAME = "gp.xml";

    /** Base URI of the actual location of all the files. */
    private static URI BASE_LOCATION = null;
    /** Location of issuer related files (e.g., ipk, credStructs). */
    private static URI ISSUER_LOCATION = null;
    /** Location of files related to a trusted party (e.g., vepk). */
    private static URI TRUSTED_PARTY_LOCATION = null;
    /** Location where updates for credentials can be fetched. */
    private static URI UPDATE_LOCATION = null;

    /** Location of proof specifications used in the tests. */
    private static URI PROOF_SPECIFICATION_LOCATION = null;
    /** Location of credentials. */
    private static URI CREDENTIAL_LOCATION = null;
    /** Location of private files (e.g., isk, ms) */
    private static URI PRIVATE_LOCATION = null;
    /** Location where all the elements that would be sent are stored. */
    private static URI SEND_LOCATION = null;

    /** ID which identify an element (this does NOT point to an actual file). */
    private static URI BASE_ID = null;
    /** ID for issuer related elements. */
    private static URI ISSUER_ID = null;
    /** ID for trusted party related elements. */
    private static URI TRUSTED_PARTY_ID = null;

    /**
     * Number of attributes an issuer key supports (i.e., number of bases
     * excluding the reserved attributes such as the master secret).
     */
    public static final int NBR_ATTRS = 9;
    /**
     * Issuer public key should have epoch length of 120 days -- 432000 seconds.
     * Note that this will require him to issuer an update for each credential
     * every 120 days.
     */
    public static final int EPOCH_LENGTH = 432000;

    public static URI gpUri;
    public static URI spUri;
    public static URI iskUri;
    public static URI ipkUri;
    public static URI msUri;
    public static URI vepkUri;
    public static URI veskUri;

    public static URI gpIdUri;
    public static URI ipkIdUri;
    public static URI vepkIdUri;

    /**
     * Load an element with a corresponding identifying URI.
     * 
     * @param objectUri
     *            URI that identifies the element.
     * @param objectLocation
     *            URI indicating the location of the URI where it will be loaded
     *            from.
     * @return Object that has been loaded.
     */
    public static Object init(URI objectUri, URI objectLocation) {
        return init(objectUri.toString(), objectLocation);
    }

    /**
     * Load an element with a corresponding identifying URI.
     * 
     * @param objectUri
     *            String representation of a URI that identifies the element.
     * @param objectLocation
     *            URI indicating the location of the URI where it will be loaded
     *            from.
     * @return Object that has been loaded.
     */
    public static Object init(String objectUri, URI objectLocation) {
        return StructureStore.getInstance().get(objectUri, objectLocation);
    }

    /**
     * Load an element from an identifying URI.
     * 
     * @param identifierUri
     *            String representation of a URI that identifies the element.
     * @return Object that has been loaded.
     */
    public static Object init(URI identifierUri) {
        return StructureStore.getInstance().get(identifierUri);
    }

    public static void initSystem(URI baseLocation, String baseUri) {
        initSystem(baseLocation.resolve(SYSTEM_PARAMETER_NAME), baseUri
                + SYSTEM_PARAMETER_NAME,
                baseLocation.resolve(GROUP_PARAMETER_NAME), baseUri
                        + GROUP_PARAMETER_NAME);
    }

    public static void initSystem(URI spLocation, String spUri, URI gpLocation,
            String gpUri) {
        URI spUri_converted = null;
        try {
            spUri_converted = new URI(spUri);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        // load system parameters
        init(spUri, spLocation);
        GroupParameters gp = (GroupParameters) init(gpUri, gpLocation);
        if (gp == null) {
            gp = GroupParameters.generateGroupParams(spUri_converted);
            try {
                XMLSerializer.getInstance().serialize(gp, gpLocation);
                init(gpUri, gpLocation);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (gp.getSystemParams() == null) {
            throw new RuntimeException("System parameters are not correctly "
                    + "referenced in group parameters at: "
                    + gpLocation.toString());
        }
    }

    /**
     * Initialise issuer with all data required.
     * 
     * @param baseLocation
     *            Location where the system parameters and group parameters can
     *            be loaded from.
     * @param baseUri
     *            URI used to refer to the system parameters and group
     *            parameters.
     * @param iskLocation
     *            Issuer secret key location (there is no URI associated with
     *            the secret key!).
     * @param ipkLocation
     *            Location of the issuer public key.
     * @param ipkUri
     *            Identifying URI of the issuer public key.
     * @return Issuer key pair.
     */
    public static IssuerKeyPair initIssuer(URI baseLocation, String baseUri,
            URI iskLocation, URI ipkLocation, URI ipkUri) {

        URI spLocation = null, gpLocation = null;
        String spId = null, gpId = null;
        if (baseLocation != null) {
            spLocation = baseLocation.resolve(SYSTEM_PARAMETER_NAME);
            gpLocation = baseLocation.resolve(GROUP_PARAMETER_NAME);
        }
        if (baseUri != null) {
            spId = baseUri + SYSTEM_PARAMETER_NAME;
            gpId = baseUri + GROUP_PARAMETER_NAME;
        }
        return initIssuer(spLocation, spId, gpLocation, gpId, iskLocation,
                ipkLocation, ipkUri);
    }

    /**
     * Convenience method.
     * 
     * @see Locations#initIssuer(URI, String, URI, String, URI, URI, URI,
     *      Integer, Integer).
     */
    public static IssuerKeyPair initIssuer(URI spLocation, String spUri,
            URI gpLocation, String gpUri, URI iskLocation, URI ipkLocation,
            URI ipkUri) {
        return initIssuer(spLocation, spUri, gpLocation, gpUri, iskLocation,
                ipkLocation, ipkUri, null, null);
    }

    /**
     * Initialise issuer with all data required.
     * 
     * @param spLocation
     *            Location of the system parameters on disk.
     * @param spUri
     *            Identifying URI of the system parameters.
     * @param gpLocation
     *            Group parameter location on disk.
     * @param gpUri
     *            Identifying URI of the group parameters.
     * @param iskLocation
     *            Issuer secret key location (there is no URI associated with
     *            the secret key!).
     * @param ipkLocation
     *            Location of the issuer public key.
     * @param ipkUri
     *            Identifying URI of the issuer public key.
     * @param numOfAttributes
     *            Maximal number of attributes supported (this number is the
     *            usable attributes excluding reserved attributes such as the
     *            master secret). Use 'null' to use the default value.
     * @param epochLength
     *            Length of one epoch for credentials issued with the given key.
     *            Use 'null' to use the default epoch length.
     * @return Issuer key pair.
     */
    public static IssuerKeyPair initIssuer(URI spLocation, String spUri,
            URI gpLocation, String gpUri, URI iskLocation, URI ipkLocation,
            URI ipkUri, Integer numOfAttributes, Integer epochLength) {
        if (epochLength == null) {
            epochLength = EPOCH_LENGTH;
        }
        if (numOfAttributes == null) {
            numOfAttributes = NBR_ATTRS;
        }

        URI gpUri_converted = null;
        if (spLocation != null && spUri != null && gpLocation != null
                && gpUri != null) {
            initSystem(spLocation, spUri, gpLocation, gpUri);

            try {
                gpUri_converted = new URI(gpUri);
            } catch (URISyntaxException e1) {
                e1.printStackTrace();
            }
        }

        // load issuer key
        IssuerKeyPair issuerKey = null;
        try {
            // try loading the public key
            init(ipkUri, ipkLocation);
            // try loading the secret key
            issuerKey = (IssuerKeyPair) init(iskLocation);
        } catch (Exception e) {
            log.log(Level.INFO, "Issuer secred key not found " + "in "
                    + iskLocation.toString() + ". I will generate "
                    + "a new one. If you are running the test case for "
                    + "the first time this is nothing to worry about!");
        }
        // NOTE (pbi) This is functionality that is only for testing purposes!
        // Clearly, one cannot simply generate a new issuer key pair just like
        // that!
        if ((issuerKey == null) || (issuerKey.getPublicKey() == null)) {
            // generating a new key
            issuerKey = new IssuerKeyPair(ipkUri, gpUri_converted,
                    numOfAttributes, epochLength);
            XMLSerializer.getInstance().serialize(issuerKey.getPublicKey(),
                    ipkLocation);
            XMLSerializer.getInstance().serialize(issuerKey.getPrivateKey(),
                    iskLocation);

            // remove previous entries in the structure store database and load
            // them through the structure store to make the right keys
            // accessible
            StructureStore.getInstance().remove(iskLocation);
            StructureStore.getInstance().remove(ipkUri);

            init(ipkUri, ipkLocation);
            init(iskLocation);
            issuerKey = (IssuerKeyPair) init(iskLocation);
        }
        return issuerKey;
    }

    /**
     * Loads the master secret from the specified location.
     */
    public static MasterSecret loadMasterSecret(URI masterSecretLocation) {
        MasterSecret masterSecret = null;
        // master secret is on a file
        masterSecret = (MasterSecret) Parser.getInstance().parse(
                masterSecretLocation);

        if (masterSecret == null) {
            log.log(Level.SEVERE, "No master secret found! Please generate "
                    + "a new one using Locations.generateMasterSecret().");
        }
        return masterSecret;
    }

    /**
     * @param groupParametersId
     *            Identifier of the group parameters (will be referenced from
     *            the master secret).
     * @param masterSecretLocation
     *            Location where the master secret will be stored.
     * @return Newly generated master secret.
     */
    public static MasterSecret generateMasterSecret(
            final URI groupParametersId, final URI masterSecretLocation) {
        MasterSecret masterSecret = new MasterSecret(groupParametersId);
        XMLSerializer.getInstance().serialize(masterSecret,
                masterSecretLocation);
        return masterSecret;
    }

    public static final VEPrivateKey initTrustedParty(URI spId,
            URI veskLocation, URI vepkLocation, URI vepkId) {
        // try to load VE keypair
        VEPublicKey pk = (VEPublicKey) StructureStore.getInstance().get(
                vepkId.toString(), vepkLocation);
        VEPrivateKey sk = (VEPrivateKey) StructureStore.getInstance().get(
                veskLocation);
        if (pk == null || sk == null) {
            log.log(Level.INFO, "Verifiable encryption key failed to load. "
                    + "Generating a new one and saving it...");
            sk = new VEPrivateKey(spId, vepkId);
            pk = sk.getPublicKey();

            XMLSerializer.getInstance().serialize(pk, vepkLocation);
            XMLSerializer.getInstance().serialize(sk, veskLocation);

            StructureStore.getInstance().remove(veskLocation);
            StructureStore.getInstance().remove(vepkId);

            init(vepkId, vepkLocation);
            init(veskLocation);
        }
        return sk;
    }

    /**
     * Initialise all paths needed for a complete test of the Identity Mixer
     * library. Note that these paths must point to actual locations (online or
     * locally) where the corresponding files are located.
     * 
     * @param baseLocation
     *            Locaiton of all files for a test of the library.
     * @deprecated
     */
    public static void initLocationsComplete(String baseLocation) {
        try {
            BASE_LOCATION = new URI(baseLocation);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        ISSUER_LOCATION = BASE_LOCATION.resolve("../issuerData/");
        TRUSTED_PARTY_LOCATION = BASE_LOCATION.resolve("../testTrustedParty/");
        UPDATE_LOCATION = BASE_LOCATION.resolve("../update/");
        // The following locations are not known to the communication
        // partner (thus there are no corresponding IDs).
        PROOF_SPECIFICATION_LOCATION = BASE_LOCATION
                .resolve("../proofSpecifications/");
        CREDENTIAL_LOCATION = BASE_LOCATION.resolve("../credentials/");
        PRIVATE_LOCATION = BASE_LOCATION.resolve("../private/");
        SEND_LOCATION = BASE_LOCATION.resolve("../send/");

        gpUri = getParameterLocation("gp");
        spUri = getParameterLocation("sp");
        iskUri = getPrivateLocation("isk");
        ipkUri = getIssuerLocation("ipk");
        msUri = getPrivateLocation("ms");
        vepkUri = getTrustedPartyLocation("vepk");
        veskUri = getPrivateLocation("vesk");
    }

    // /**
    // * Initialise the URIs that are used within the XML files. We use those
    // URIs
    // * as we don't want to use locations on the local file system within the
    // * files.
    // *
    // * @param baseId
    // * Base URI (e.g.,
    // * <code>http://www.zurich.ibm.com/security/idmx/v2</code>)
    // * @return System parameters loaded from a local file (according to the
    // * location information).
    // * @deprecated
    // */
    // public static SystemParameters initIdsComplete(String baseId) {
    // // IDs for the public parameters
    // SystemParameters sp = initBaseId(baseId);
    // initIssuerId(BASE_ID.resolve("testIssuer/").toString());
    // initTrustedPartyId(BASE_ID.resolve("testTrustedParty/").toString());
    // return sp;
    // }

    /**
     * @deprecated
     */
    public static final SystemParameters initBaseId(String baseId) {
        try {
            BASE_ID = new URI(baseId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        gpIdUri = getParameterId("gp");

        SystemParameters sp = (SystemParameters) init(getParameterId("sp"),
                spUri);
        GroupParameters gp = (GroupParameters) init(gpIdUri, gpUri);
        if (gp == null) {
            gp = GroupParameters.generateGroupParams(spUri);
            try {
                XMLSerializer.getInstance().serialize(gp, gpUri);
                init(gpIdUri, gpUri);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (gp.getSystemParams() == null) {
            throw new RuntimeException("System parameters are not correctly "
                    + "referenced in group parameters: " + gpUri.toString());
        }
        return sp;
    }

    /**
     * @deprecated
     */
    public static final IssuerPublicKey initIssuerId(String issuerId) {
        try {
            ISSUER_ID = new URI(issuerId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        ipkIdUri = getIssuerId("ipk");
        return getIssuerPublicKey();
    }

    // /**
    // * @deprecated
    // */
    // protected static final VEPublicKey initTrustedPartyId(String
    // trustedPartyId) {
    // try {
    // TRUSTED_PARTY_ID = new URI(trustedPartyId);
    // } catch (URISyntaxException e) {
    // e.printStackTrace();
    // }
    // vepkIdUri = getTrustedPartyId("vepk");
    // return getVEPublicKey();
    // }

    // /**
    // * @deprecated
    // */
    // public static SystemParameters loadParameters(String baseId,
    // String baseLocation) {
    // // init URIs with the correct values
    // initLocationsComplete(baseLocation);
    //
    // // loading of structures from files (as they are not located in the
    // // location indicated in the file).
    // return initIdsComplete(baseId);
    // }

    /**
     * @deprecated
     */
    public static final UpdateSpecification loadUpdateSpecification(String name) {
        name = "updateSpecification_" + name;
        URI updateSpecUri = getIssuerLocation(name);
        return (UpdateSpecification) init(getIssuerId(name), updateSpecUri);
    }

    /**
     * @deprecated
     */
    public static final void loadCredStruct(String name) {
        URI credStructUri = getIssuerLocation(name);
        init(getIssuerId(name), credStructUri);
    }

    /**
     * @deprecated
     */
    public static final URI getUpdateLocation() {
        if (UPDATE_LOCATION != null) {
            return UPDATE_LOCATION;
        } else {
            throw new RuntimeException("Update location not initialised!");
        }
    }

    /**
     * @deprecated
     */
    public static final URI getCredentialLocation() {
        if (CREDENTIAL_LOCATION != null) {
            return CREDENTIAL_LOCATION;
        } else {
            throw new RuntimeException("Credential location not initialised!");
        }
    }

    /**
     * @deprecated
     */
    protected static final String getFileExtension(String fileBaseName) {
        return fileBaseName + ".xml";
    }

    /**
     * @deprecated
     */
    protected static final URI getParameterLocation(String fileBaseName) {
        return BASE_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    protected static final URI getParameterId(String fileBaseName) {
        return BASE_ID.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    protected static final URI getIssuerLocation(String fileBaseName) {
        return ISSUER_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    public static final URI getIssuerId(String fileBaseName) {
        return ISSUER_ID.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    public static final URI getTrustedPartyLocation(String fileBaseName) {
        return TRUSTED_PARTY_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    protected static final URI getTrustedPartyId(String fileBaseName) {
        return TRUSTED_PARTY_ID.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    public static final URI getProofSpecLocation(String fileBaseName) {
        return PROOF_SPECIFICATION_LOCATION.resolve(fileBaseName + ".xml");
    }

    /**
     * @deprecated
     */
    public static final URI getCredentialLocation(String fileBaseName) {
        return CREDENTIAL_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    public static final URI getPrivateLocation(String fileBaseName) {
        return PRIVATE_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    /**
     * @deprecated
     */
    public static URI getSendLocation(String fileBaseName) {
        return SEND_LOCATION.resolve(fileBaseName + ".xml");
    }

    /**
     * @deprecated
     */
    public static URI getProofLocation(String fileBaseName) {
        return getSendLocation(fileBaseName + "_proof");
    }

    /**
     * @deprecated
     */
    public static URI getNonceLocation(String fileBaseName) {
        return getSendLocation(fileBaseName + "_nonce");
    }

    /**
     * @deprecated
     */
    protected static IssuerPublicKey getIssuerPublicKey() {
        return (IssuerPublicKey) StructureStore.getInstance().get(
                ipkIdUri.toString(), ipkUri);
    }

    /**
     * @deprecated
     */
    public static IssuerKeyPair getIssuerKeyPair() {
        IssuerKeyPair issuerKey = null;
        try {
            issuerKey = (IssuerKeyPair) StructureStore.getInstance().get(
                    Locations.iskUri);
        } catch (Exception e) {
            log.log(Level.INFO, "Issuer secred key not found in "
                    + Locations.iskUri.toString() + ". I will generate "
                    + "a new one. If you are running the test case for "
                    + "the first time this is nothing to worry about!");
        }
        if ((issuerKey == null) || (issuerKey.getPublicKey() == null)) {
            issuerKey = new IssuerKeyPair(Locations.ipkIdUri,
                    Locations.gpIdUri, NBR_ATTRS, EPOCH_LENGTH);
            XMLSerializer.getInstance().serialize(issuerKey.getPublicKey(),
                    Locations.ipkUri);
            XMLSerializer.getInstance().serialize(issuerKey.getPrivateKey(),
                    Locations.iskUri);

            // remove previous entries in the structure store database and load
            // them through the structure store to make the right keys
            // accessible
            StructureStore.getInstance().remove(Locations.iskUri);
            StructureStore.getInstance().remove(Locations.ipkIdUri);

            getIssuerPublicKey();
            issuerKey = (IssuerKeyPair) StructureStore.getInstance().get(
                    Locations.iskUri);
        }

        return issuerKey;
    }

}
