/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.credsystem;

import java.io.StringReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.xml.sax.InputSource;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.utils.Parser;
import com.ibm.zurich.idmx.utils.XMLSerializer;

/**
 *
 */
public class Credsystem {

    /** Credential store. */
    private CredentialStore credentialStore;

    private List<URI> usedCredentials = new ArrayList<URI>();

    public Credsystem(CredentialStore theCredentialStore) {
        credentialStore = theCredentialStore;
    }

    /**
     * Constructor. Only for a demonstrator implemented within the PrimeLife
     * project.
     */
    public Credsystem() {
        // // init the basic locations on the local system
        // Locations.initLocationsComplete("file:/var/www/common-room/idmx/"
        // + "parameter/");
        //
        // // load the idmx system parameters
        // Locations.initBaseId("http://www.zurich.ibm.com/security/idmx/v2/");
        //
        // // load the issuer public key with the general utopia uri
        // Locations.initIssuerId("http://www.utopia.ut/security/idmx/");

        // URIs and locations for the user (prover in this case)
        URI baseLocation = null, credStructLocation = null, ipkLocation = null;
        try {
            // init prover locations and URIs
            baseLocation = new URI(
                    "file:///var/www/common-room/idmx/parameter/");
            ipkLocation = baseLocation.resolve("../issuerData/ipk.xml");
            credStructLocation = baseLocation
                    .resolve("../issuerData/CredentialStructureUtopia.xml");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        Locations.initSystem(baseLocation,
                "http://www.zurich.ibm.com/security/idmx/v2/");
        Locations.init("http://www.utopia.ut/security/idmx/ipk.xml",
                ipkLocation);
        Locations.init("http://www.utopia.ut/identityCard/"
                + "v2012/CredentialStructureUtopia.xml", credStructLocation);

        // credentialStore = CredentialStore.get("123457",
        // baseLocation.resolve("../credentials/"),
        // baseLocation.resolve("../credentials/ms.xml"),
        // baseLocation.resolve(Locations.GROUP_PARAMETER_NAME));
    }

    public String getCredentialStrings(String authCode) {
        String credentials = "";
        String endl = System.getProperty("line.separator");
        if (credentialStore.authenticate(authCode)) {
            Iterator<URI> iterator = credentialStore.getCredentials().keySet()
                    .iterator();
            while (iterator.hasNext()) {
                credentials += credentialStore.getCredentialString(iterator
                        .next()) + endl;
            }
        }
        return credentials;
    }

    // /**
    // * @param credName
    // * File name of the credential.
    // * @param tempCredName
    // * Temporary name of the credential in the proof specification.
    // * @return
    // */
    // private HashMap<String, Credential> loadCredentials(
    // HashMap<String, URI> credentialMapping) {
    // HashMap<String, Credential> credentialMap = new HashMap<String,
    // Credential>();
    //
    // Iterator<String> iterator = credentialMapping.keySet().iterator();
    // while (iterator.hasNext()) {
    // String tempCredName = iterator.next();
    // Credential cred = credentialStore.getCredential(credentialMapping
    // .get(tempCredName));
    // credentialMap.put(tempCredName, cred);
    // }
    // return credentialMap;
    // }

    public String requestProof(String authCode, String proofSpecification,
            String nonceString) {
        InputSource is = new InputSource();
        is.setCharacterStream(new StringReader(proofSpecification));
        ProofSpec spec = (ProofSpec) Parser.getInstance().parse(is);
        return getProofString(compileProof(authCode, spec, nonceString));
    }

    public Proof requestProof(String authCode, ProofSpec spec,
            String nonceString) {
        return compileProof(authCode, spec, nonceString);
    }

    private Proof compileProof(String authCode, ProofSpec spec,
            String nonceString) {
        // first get the nonce (done by the verifier)
        BigInteger nonce = new BigInteger(nonceString);

        // add the credentials to the currently used credentials
        HashMap<String, Credential> creds = new HashMap<String, Credential>();

        URI baseLocation = null;
        try {
            baseLocation = new URI("file:///var/www/common-room/"
                    + "idmx/parameter/");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        credentialStore = CredentialStore.get(authCode,
                baseLocation.resolve("../credentials/"),
                baseLocation.resolve("../credentials/ms.xml"),
                baseLocation.resolve(Locations.GROUP_PARAMETER_NAME));

        // TODO (pbi) this is a very limited approach (we use it in a demo)!!!
        Set<URI> credentialSet = credentialStore.getCredentials().keySet();
        Iterator<URI> iterator = credentialSet.iterator();
        URI credential = null;
        while (iterator.hasNext()) {
            URI tempCredential = iterator.next();
            if (!usedCredentials.contains(tempCredential)) {
                usedCredentials.add(tempCredential);
                credential = tempCredential;
                break;
            }
        }
        if (credential == null) {
            if (usedCredentials.isEmpty()) {
                throw new RuntimeException("Credential store is empty.");
            }
            credential = usedCredentials.get(usedCredentials.size() - 1);
        }

        creds.put(spec.getCredTempNames().iterator().next(),
                (Credential) credentialStore.getCredentials().get(credential));

        Prover prover = new Prover(credentialStore.getMasterSecret(), creds);

        // create the proof
        Proof p = prover.buildProof(nonce, spec);

        credentialStore.close();
        return p;
    }

    public String getProofString(Proof proof) {
        String proofString = null;
        try {
            proofString = XMLSerializer.getInstance().serialize(proof);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // save the proof
        return proofString;
    }

}
