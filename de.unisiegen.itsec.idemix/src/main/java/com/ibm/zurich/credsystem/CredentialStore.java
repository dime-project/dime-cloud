/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.credsystem;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.credsystem.Translator.HighLevelDataType;
import com.ibm.zurich.credsystem.utils.Parser;
import com.ibm.zurich.credsystem.utils.Utils;
import com.ibm.zurich.credsystem.utils.XMLSerializer;
import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.MasterSecret;

/**
 * Utility class that contains credentials that the user owns. All access to
 * credentials must be handled through this class.
 */
public class CredentialStore {

    /** Hash length for authentication information. */
    private static final int HASH_LEN = 256;

    /** Logger. */
    private static Logger log = Logger.getLogger(CredentialStore.class
            .getName());

    /** Map of all currently active credential stores. */
    private static HashMap<URI, CredentialStore> credStoreMap = new HashMap<URI, CredentialStore>();

    /** Information used to authenticate to the credential store. */
    private String authenticationCode = null;
    /** Location of the credentials. */
    private URI credentialStoreLocation;
    /** Location of the master secret. */
    private URI masterSecretLocation;
    private MasterSecret masterSecret;
    /** Location of the group parameters. */
    private URI groupParamsLocation;
    /** Translator for this credential store. */
    private Translator translator;
    /** Credentials that are in the credential store. */
    private HashMap<URI, Credential> credentialMap;

    /**
     * Constructor.
     * 
     * @param storeLocation
     *            Location of this credential store.
     * @param msLocation
     *            Location of the Master Secret.
     * @param groupParametersLocation
     *            Location of the group parameters (needed if the master secret
     *            needs to be created).
     */
    private CredentialStore(final String authCode, final URI storeLocation,
            final URI msLocation, final URI groupParametersLocation) {
        credentialStoreLocation = storeLocation;
        masterSecretLocation = msLocation;
        groupParamsLocation = groupParametersLocation;
    }

    /**
     * Loads all credentials in the indicated location.
     * 
     * @param storeLocation
     *            Location where credentials reside.
     * @param msLocation
     *            Location of the master secret, which may be different from the
     *            location of the credential store itself.
     */
    public static CredentialStore get(final String authCode,
            final URI storeLocation, final URI msLocation,
            final URI groupParametersLocation) {
        CredentialStore credStore = credStoreMap.get(storeLocation);
        if (credStore == null) {
            credStore = new CredentialStore(authCode, storeLocation,
                    msLocation, groupParametersLocation);
            try {
                credStore.load(authCode);
            } catch (FileNotFoundException e) {
                log.log(Level.SEVERE, "Credential store cannot be created in "
                        + "the given location.");
            }
            credStoreMap.put(storeLocation, credStore);
            return credStore;
        }
        credStore.update(authCode);
        return credStore;
    }

    /**
     * Loads the basic files for the credential store (e.g., the translator).
     * 
     * @throws FileNotFoundException
     */
    private final void load(String authCode) throws FileNotFoundException {
        if (credentialStoreLocation.getScheme().equalsIgnoreCase("file")) {
            String[] files = getFiles("translator");
            if (files != null && files.length == 1) {
                translator = (Translator) Parser.getInstance().parse(
                        credentialStoreLocation.resolve(files[0]));
            } else {
                translator = new Translator();
            }
        } else {
            throw new RuntimeException("Scheme of credential store is not "
                    + "supported.");
        }

        if (credentialStoreLocation.getScheme().equalsIgnoreCase("file")) {
            credentialMap = new HashMap<URI, Credential>();
            update(authCode);
        } else {
            throw new RuntimeException("Scheme of credential store is not "
                    + "supported.");
        }

        if (masterSecretLocation.getScheme().equalsIgnoreCase("file")) {
            masterSecret = (MasterSecret) Parser.getInstance().parse(
                    masterSecretLocation);
            if (masterSecret == null) {
                masterSecret = new MasterSecret(groupParamsLocation);
            }
        } else {
            throw new RuntimeException("Scheme of master secret location is "
                    + "not supported.");
        }
    }

    /**
     * @param nameFilter
     *            Defines a filter on the beginning of a file name.
     * @return List of files in the credential directory that end with
     *         <tt>.xml</tt>.
     */
    private final String[] getFiles(final String nameFilter) {
        File dir = new File(credentialStoreLocation);
        FilenameFilter filter = new FilenameFilter() {
            public boolean accept(File dir, String name) {
                if (name.endsWith(".xml") && name.startsWith(nameFilter)) {
                    return true;
                }
                return false;
            }
        };
        return dir.list(filter);
    }

    /**
     * Scans the credential location for new credentials and loads them.
     */
    @SuppressWarnings("unchecked")
    private final void update(String authCode) {
        String[] files;

        if (authenticationCode == null) {
            // load authentication code
            files = getFiles("storeInformation");

            if (files != null && files.length == 1) {
                    authenticationCode = (String) Parser.getInstance().parse(
                            credentialStoreLocation.resolve(files[0]));
                } else {
                	if (files.length > 1) {
                    throw new RuntimeException("There are several store "
                            + "information files within this store. The "
                            + "integrity of this store is no longer given. "
                            + "We suggest to create a new store.");
                } else {
                    authenticationCode = Utils.hashString(authCode, HASH_LEN)
                            .toString();                	
                }
            } 
        } 

        // authenticate
        if (!authenticate(authCode)) {
            throw new RuntimeException("Authentication to credential "
                    + "store failed.");
        }

        log.log(Level.INFO, "Updating the credential store.");

        files = getFiles("credentialMap");
        if (files != null) {
            if (files.length == 1) {
                HashSet<URI> credentialLocations = (HashSet<URI>) Parser
                        .getInstance().parse(
                                credentialStoreLocation.resolve(files[0]));

                Iterator<URI> it = credentialLocations.iterator();
                while (it.hasNext()) {
                    URI credentialIdentifier = it.next();
                    if (!credentialMap.containsKey(credentialIdentifier)) {
                        Credential cred = (Credential) Parser.getInstance()
                                .parse(credentialIdentifier);
                        credentialMap.put(credentialIdentifier, cred);
                    }
                }
            } else if (files.length > 1) {
                throw new RuntimeException("There are several credential "
                        + "maps within this store. The integrity of this "
                        + "store is no longer given. We suggest to create "
                        + "a new store.");
            }
        }
    }

    /**
     * Delegation method. This method delegates the request to the right
     * translator.
     * 
     * @param date
     *            Date to be encoded.
     * @param dataType
     *            Method of encoding.
     * @return BigInteger encoding the given date w.r.t. the given encoding.
     */
    public BigInteger encode(String date, HighLevelDataType dataType) {
        return translator.encode(date, dataType);
    }

    /**
     * Delegation method. This method delegates the request to the right
     * translator.
     * 
     * @param l_H
     *            Length of the hash function output.
     * @param value
     *            String to be encoded.
     * @return Encoding of the string by creating a hash.
     */
    public BigInteger encode(int l_H, String value) {
        return translator.encode(l_H, value);
    }

    /**
     * Delegation method. This method delegates the request to the right
     * translator.
     * 
     * @param encodedValue
     *            String to be decoded.
     * @return Decoded string.
     */
    public Object decode(BigInteger encodedValue) {
        return translator.decode(encodedValue);
    }

    /**
     * Gracefully closes a credential store (e.g., by writing the translation
     * map to a file).
     */
    public final void close() {
        XMLSerializer.getInstance().serialize(translator,
                credentialStoreLocation.resolve("translator.xml"));
        XMLSerializer.getInstance().serialize(masterSecret,
                masterSecretLocation);
        XMLSerializer.getInstance().serialize(credentialMap,
                credentialStoreLocation.resolve("credentialMap.xml"));
        credStoreMap.remove(credentialStoreLocation);
        XMLSerializer.getInstance().serialize(authenticationCode,
                credentialStoreLocation.resolve("storeInformation.xml"));
    }

    /**
     * @return Master secret
     */
    public final MasterSecret getMasterSecret() {
        return masterSecret;
    }

    /**
     * @param credentialId
     *            URI of a credential within the credential store.
     * @return Credential from the given URI.
     */
    public Credential getCredential(URI credentialId) {
        if (credentialMap.containsKey(credentialId)) {
            return credentialMap.get(credentialId);
        } else {
            return null;
        }
    }

    public String getCredentialString(URI credentialId) {
        if (credentialMap.containsKey(credentialId)) {
            String delimiter = "::";
            String attDelimiter = "--";
            String credentialString = delimiter + "cred" + delimiter;

            Credential cred = credentialMap.get(credentialId);
            // preamble of the credential
            credentialString += cred.getCredStructId().toString() + delimiter;

            List<Attribute> atts = cred.getAttributes();
            for (Attribute att : atts) {
                credentialString += att.getName() + attDelimiter;
                credentialString += translator.decode(att.getValue())
                        + delimiter;
            }
            return credentialString;
        } else {
            return null;
        }
    }

    /**
     * @return All credentials contained in this credential store.
     */
    public HashMap<URI, Credential> getCredentials() {
        return credentialMap;
    }

    /**
     * @param credentialIds
     *            Set of credential identifiers (URIs) that are needed to
     *            compile a proof.
     * @return Map with the credentials identified by the <tt>credentialIds</tt>
     *         .
     */
    public HashMap<URI, Credential> getCredentials(HashSet<URI> credentialIds) {

        final HashMap<URI, Credential> credentialSet = new HashMap<URI, Credential>();

        Iterator<URI> iterator = credentialIds.iterator();
        while (iterator.hasNext()) {
            URI credentialId = iterator.next();
            if (credentialMap.containsKey(credentialId)) {
                credentialSet.put(credentialId, getCredential(credentialId));
            }
        }
        return credentialSet;
    }

    /**
     * @param credentialId
     *            URI of a credential within the credential store.
     * @return Copy of the credential from the given URI.
     */
    public Credential getCredentialCopy(URI credentialId) {
        if (credentialMap.containsKey(credentialId)) {
            return (Credential) Parser.getInstance().parse(credentialId);
        } else {
            return null;
        }
    }

    /**
     * @param credentialId
     *            URI of a credential within the credential store.
     * @return Credential with high level data as attribute values instead of
     *         their encodings.
     */
    public Credential getTranslatedCredential(URI credentialId) {
        Credential cred = getCredentialCopy(credentialId);
        Iterator<Attribute> iterator = cred.getAttributes().iterator();
        while (iterator.hasNext()) {
            Attribute att = iterator.next();
            att.setValueObject(translator.decode(att.getValue()));
        }
        return cred;
    }

    /**
     * Adds a credential to the credential store.
     * 
     * @param credential
     *            Credential to be added.
     * @param information
     *            Information about the credential store (e.g., pictures) but it
     *            is currently not used!
     * @return Name assigned to the credential.
     */
    public URI put(Credential credential, Object information) {
        // TODO pbi: use credential store information and define what this
        // should be
        URI name = credentialStoreLocation.resolve("Credential_"
                + Utils.getRandomString(12) + ".xml");
        XMLSerializer.getInstance().serialize(credential, name);
        credentialMap.put(name, credential);
        return name;
    }

    /**
     * @param authCode
     *            Authentication code used to unlock the store.
     */
    public boolean authenticate(String authCode) {
        return (Utils.hashString(authCode, HASH_LEN).toString()
                .equalsIgnoreCase(authenticationCode));
    }

	public void clean() {
		// TODO (pbi): delete files used for this credential store
	}
}
