/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.idmx.utils;

import java.io.File;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.DomNym;
import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.dm.Nym;
import com.ibm.zurich.idmx.dm.Credential.UpdateInformation;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPrivateKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGAND;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGNOT;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGOR;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.showproof.sval.SValuesProveCL;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;
import com.ibm.zurich.idmx.ve.VerifiableEncryptionOpening;

/**
 * Class for object serialization to XML.
 */
public class XMLSerializer {

    /** Singleton design pattern. */
    private static XMLSerializer serializer;

    private Document doc;

    /**
     * Constructor.
     */
    protected XMLSerializer() {
        super();
    }

    /**
     * Singleton design pattern.
     * 
     * @return Parser object.
     */
    public static XMLSerializer getInstance() {
        if (serializer == null) {
            serializer = new XMLSerializer();
        }
        return serializer;
    }

    protected Document createDocument() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = null;
        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        return db.newDocument();
    }

    /**
     * @param object
     * @return
     * @throws ParserConfigurationException
     */
    protected Document createDOM(Object object) {
        // Document doc = null;
        doc = createDocument();

        if (object instanceof GroupParameters) {
            serializeGroupParameters((GroupParameters) object);
        } else if (object instanceof IssuerPublicKey) {
            serializeIssuerPublicKey((IssuerPublicKey) object);
        } else if (object instanceof IssuerPrivateKey) {
            serializeIssuerPrivateKey((IssuerPrivateKey) object);
        } else if (object instanceof VEPublicKey) {
            serializeVerEncPublicKey((VEPublicKey) object);
        } else if (object instanceof VEPrivateKey) {
            serializeVerEncPrivateKey((VEPrivateKey) object);
        } else if (object instanceof MasterSecret) {
            serializeMasterSecret((MasterSecret) object);
        } else if (object instanceof Credential) {
            serializeCredential((Credential) object);
        } else if (object instanceof Proof) {
            serializeProof((Proof) object);
        } else if (object instanceof BigInteger) {
            serializeNonce((BigInteger) object);
        } else if (object instanceof IssuerUpdateInformation) {
            serializeIssuerUpdateInformation((IssuerUpdateInformation) object);
        } else if (object instanceof Message) {
            serializeMessage((Message) object);
        } else if (object instanceof VerifiableEncryptionOpening) {
            serializeVerifiableEncryptionOpening((VerifiableEncryptionOpening) object);
        } else if (object instanceof VerifiableEncryption) {
            serializeVerifiableEncryption((VerifiableEncryption) object);
        }
        return doc;
    }

    protected void output(Source source, Result result) {

        try {
            Transformer transformer = TransformerFactory.newInstance()
                    .newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(
                    "{http://xml.apache.org/xslt}indent-amount", "2");
            transformer.transform(source, result);
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }

    public String serialize(Object object) {
        Document doc = createDOM(object);

        DOMSource source = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        output(source, result);

        return writer.toString();
    }

    public void serialize(Object object, URI filename) {
        Document doc = createDOM(object);

        try {
            Source source = new DOMSource(doc);
            File file = new File(filename);
            Result result = new StreamResult(file);
            output(source, result);
        } catch (TransformerFactoryConfigurationError e) {
            e.printStackTrace();
        }
    }

    protected void setRootAttributes(Element root) {
        String name = root.getNodeName();

        root.setAttribute("xmlns", Constants.XML_NAMESPACE);
        root.setAttribute("xmlns:xsi", Constants.XML_SCHEMA_INSTANCE);
        root.setAttribute("xmlns:xs", Constants.XML_SCHEMA);
        root.setAttribute("xsi:schemaLocation", Constants.XML_NAMESPACE + " "
                + name + ".xsd");
    }

    /**
     * Convenience: Appends a value <code>value</code> to the parent node, where
     * the format is of the following form:
     * 
     * <pre>
     *  &lt;name&gt;
     *     value
     *  &lt;/name&gt;
     * </pre>
     * 
     * @param value
     *            Value to be serialized.
     * @param name
     *            Name to be used for the element.
     * @param doc
     *            Document.
     * @param parent
     *            Parent where the element should be attached.
     */
    private final void serializeObject(Object value, String name, Element parent) {
        Element element = doc.createElement(name);
        Text text = doc
                .createTextNode(((value == null) ? "" : value.toString()));
        element.appendChild(text);
        parent.appendChild(element);

    }

    private final Document serializeGroupParameters(GroupParameters gp) {
        Element root = doc.createElement("GroupParameters");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);

        serializeObject(gp.getSystemParamsLocation(), "SystemParameters",
                references);

        Element elements = doc.createElement("Elements");
        root.appendChild(elements);

        serializeObject(gp.getCapGamma(), "Gamma", elements);
        serializeObject(gp.getG(), "g", elements);
        serializeObject(gp.getH(), "h", elements);
        serializeObject(gp.getRho(), "rho", elements);

        return doc;
    }

    private final Document serializeIssuerPublicKey(IssuerPublicKey ipk) {
        Element root = doc.createElement("IssuerPublicKey");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);

        serializeObject(ipk.getGroupParamsLocation(), "GroupParameters",
                references);

        Element elements = doc.createElement("Elements");
        root.appendChild(elements);

        serializeObject(ipk.getCapS(), "S", elements);
        serializeObject(ipk.getCapZ(), "Z", elements);
        serializeObject(ipk.getN(), "n", elements);

        Element bases = doc.createElement("Bases");
        bases.setAttribute("num", Integer.toString(ipk.getMaxNbrAttrs()));
        elements.appendChild(bases);

        BigInteger[] capR = ipk.getCapR();

        for (int i = 0; i < ipk.getMaxNbrAttrs(); ++i) {
            serializeObject(capR[i], "Base_" + i, bases);
        }

        Element features = doc.createElement("Features");
        root.appendChild(features);

        Element element;
        if (ipk.hasEpoch()) {
            element = doc.createElement("Epoch");
            element.setAttribute("length",
                    Integer.toString(ipk.getEpochLength()));
            features.appendChild(element);
        }
        return doc;
    }

    private final Document serializeIssuerPrivateKey(IssuerPrivateKey isk) {
        Element root = doc.createElement("IssuerPrivateKey");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);
        serializeObject(isk.getPublicKeyLocation(), "IssuerPublicKey",
                references);

        Element elements = doc.createElement("Elements");
        root.appendChild(elements);

        serializeObject(isk.getN(), "n", elements);
        serializeObject(isk.getP(), "p", elements);
        serializeObject(isk.getPPrime(), "pPrime", elements);
        serializeObject(isk.getQ(), "q", elements);
        serializeObject(isk.getQPrime(), "qPrime", elements);

        return doc;
    }

    private final Document serializeVerEncPublicKey(VEPublicKey pk) {
        Element root = doc.createElement("VerifiableEncryptionPublicKey");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);
        serializeObject(pk.getSystemParametersLocation(), "SystemParameters",
                references);

        Element elements = doc.createElement("Elements");
        root.appendChild(elements);

        serializeObject(pk.getG(), "g", elements);
        serializeObject(pk.getN(), "n", elements);
        serializeObject(pk.getY1(), "y1", elements);
        serializeObject(pk.getY2(), "y2", elements);
        serializeObject(pk.getY3(), "y3", elements);

        return doc;
    }

    private final Document serializeVerEncPrivateKey(VEPrivateKey sk) {
        Element root = doc.createElement("VerifiableEncryptionPrivateKey");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);
        serializeObject(sk.getPublicKeyLocation(),
                "VerifiableEncryptionPublicKey", references);

        Element elements = doc.createElement("Elements");
        root.appendChild(elements);

        serializeObject(sk.getOrderN(), "orderN", elements);
        serializeObject(sk.getX1(), "x1", elements);
        serializeObject(sk.getX2(), "x2", elements);
        serializeObject(sk.getX3(), "x3", elements);

        return doc;
    }

    private final Document serializeMasterSecret(MasterSecret masterSecret) {
        Element root = doc.createElement("MasterSecret");
        setRootAttributes(root);
        doc.appendChild(root);

        // Serialise value
        serializeObject(masterSecret.getValue(), "Value", root);

        // serialise group parameters location
        serializeObject(masterSecret.getGroupParametersLocation(),
                "GroupParameters", root);

        // Serialise pseudonyms
        Element elements = doc.createElement("Pseudonyms");
        HashMap<String, Nym> nymMap = masterSecret.getNymList();
        Iterator<String> iterator = nymMap.keySet().iterator();

        Element element;
        Text text;
        while (iterator.hasNext()) {
            String name = iterator.next();
            Nym nym = nymMap.get(name);

            element = doc.createElement("Pseudonym");
            element.setAttribute("name", name);
            text = doc.createTextNode(nym.getRandom().toString());
            element.appendChild(text);
            elements.appendChild(element);
        }
        root.appendChild(elements);

        // Serialise domain pseudonyms
        elements = doc.createElement("DomainPseudonyms");
        HashMap<String, DomNym> domNymMap = masterSecret.getDomNymList();
        iterator = domNymMap.keySet().iterator();

        while (iterator.hasNext()) {
            String name = iterator.next();
            element = doc.createElement("DomainPseudonym");
            element.setAttribute("name", name);

            DomNym domNym = domNymMap.get(name);
            String g_Dom = domNym.getG_dom().toString();
            element.setAttribute("g_Dom", g_Dom);
            text = doc.createTextNode(domNym.getNym().toString());
            element.appendChild(text);

            elements.appendChild(element);
        }
        root.appendChild(elements);

        return doc;
    }

    private final Document serializeCredential(Credential cred) {
        Element root = doc.createElement("Credential");
        setRootAttributes(root);
        doc.appendChild(root);

        Element references = doc.createElement("References");
        root.appendChild(references);

        serializeObject(cred.getIssuerPublicKeyId(), "IssuerPublicKey",
                references);
        serializeObject(cred.getCredStructId(), "CredentialStructure",
                references);

        Element attributes = doc.createElement("Attributes");
        root.appendChild(attributes);

        List<Attribute> attrs = cred.getAttributes();

        for (Attribute attr : attrs) {
            Element attribute = doc.createElement("Attribute");
            attribute.setAttribute("name", attr.getName());
            attributes.appendChild(attribute);

            Object valueObject = attr.getValueObject();

            if (valueObject instanceof BigInteger) {
                serializeObject(valueObject, "Value", attribute);

            } else if (valueObject instanceof Commitment) {
                Commitment c = (Commitment) valueObject;

                Element commitment = doc.createElement("Commitment");
                attribute.appendChild(commitment);

                serializeObject(c.getCommitment(), "commitment", commitment);
                serializeObject(c.getCapS(), "S", commitment);
                serializeObject(c.getN(), "n", commitment);

                Element bases = doc.createElement("Bases");
                bases.setAttribute("num", Integer.toString(c.getNumBases()));
                commitment.appendChild(bases);

                for (int i = 0; i < c.getNumBases(); ++i) {
                    serializeObject(c.getMsgBase(i), "Base", bases);
                }

                Element commitmentOpening = doc
                        .createElement("CommitmentOpening");
                commitment.appendChild(commitmentOpening);

                Element messages = doc.createElement("Messages");
                commitmentOpening.appendChild(messages);

                CommitmentOpening co = (CommitmentOpening) c;

                for (int i = 0; i < co.getNumBases(); ++i) {
                    serializeObject(co.getMessage(i), "Message", messages);
                }
                serializeObject(co.getRandom(), "rand", commitmentOpening);
            }

            if (attr.getPrimeFactors() != null) {

                Iterator<String> itr = attr.getPrimeFactors().iterator();

                while (itr.hasNext()) {
                    serializeObject(itr.next(), "EnumValue", attribute);
                }
            }
        }

        Element signature = doc.createElement("Signature");
        root.appendChild(signature);

        serializeObject(cred.getCapA(), "A", signature);
        serializeObject(cred.getE(), "e", signature);
        serializeObject(cred.getV(), "v", signature);

        Element features = doc.createElement("Features");
        root.appendChild(features);

        UpdateInformation updateInfo = cred.getUpdateInformation();

        if (updateInfo != null) {
            Element updates = doc.createElement("Updates");
            features.appendChild(updates);

            serializeObject(updateInfo.getUpdateLocation(),
                    "UpdateSpecification", updates);
            serializeObject(updateInfo.getCapU(), "capU", updates);
            serializeObject(updateInfo.getVPrime(), "vPrime", updates);
            serializeObject(updateInfo.getNonce(), "nonce", updates);
            serializeObject(updateInfo.getContext(), "context", updates);
        }

        return doc;
    }

    private final Document serializeProof(Proof proof) {
        Element root = doc.createElement("IdmxProof");
        setRootAttributes(root);
        doc.appendChild(root);

        serializeProofElements(proof, root);

        return doc;
    }

    private Document serializeProofElements(Proof proof, Element root) {
        Text text = null;

        if (proof.getChallenge() != null) {
            serializeObject(proof.getChallenge(), "Challenge", root);
        }

        Element commonValues = doc.createElement("CommonValues");
        TreeMap<String, BigInteger> commonList = proof.getCommonList();
        Iterator<String> iterator = commonList.keySet().iterator();

        while (iterator.hasNext()) {
            String key = iterator.next();
            Element commonValue = doc.createElement("CommonValue");
            commonValue.setAttribute("key", key);
            text = doc.createTextNode(commonList.get(key).toString());
            commonValue.appendChild(text);
            commonValues.appendChild(commonValue);
        }
        root.appendChild(commonValues);

        Element values = doc.createElement("Values");
        Map<String, SValue> sValues = proof.getSValues();
        iterator = sValues.keySet().iterator();

        while (iterator.hasNext()) {
            String key = iterator.next();
            Element value = doc.createElement("Value");
            value.setAttribute("key", key);

            Object sValue = sValues.get(key).getValue();
            if (sValue instanceof BigInteger) {
                value.setAttribute("type", "BigInteger");
                text = doc.createTextNode(sValue.toString());
                value.appendChild(text);
            } else if (sValue instanceof SValuesIP) {
                value.setAttribute("type", "SValueIP");
                SValuesIP valueIP = (SValuesIP) sValue;
                Element sValueIP = doc.createElement("SValueIP");

                serializeObject(valueIP.getAlphaHat(), "AlphaHat", sValueIP);

                BigInteger[] uHat = valueIP.getUHat();
                for (int i = 0; i < uHat.length; i++) {
                    serializeObject(uHat[i], "uHat_" + i, sValueIP);
                }
                BigInteger[] rHat = valueIP.getRHat();
                for (int i = 0; i < rHat.length; i++) {
                    serializeObject(rHat[i], "rHat_" + i, sValueIP);
                }
                value.appendChild(sValueIP);
            } else if (sValue instanceof SValuesProveCL) {
                value.setAttribute("type", "SValueProveCL");
                SValuesProveCL valueProveCL = (SValuesProveCL) sValue;
                Element sValueProveCL = doc.createElement("SValueProveCL");

                serializeObject(valueProveCL.getEHat(), "eHat", sValueProveCL);
                serializeObject(valueProveCL.getVHatPrime(), "vHatPrime",
                        sValueProveCL);

                value.appendChild(sValueProveCL);
            } else if (sValue instanceof SValuesCGAND) {
                value.setAttribute("type", "SValueCGAND");
                SValuesCGAND valueCGAND = (SValuesCGAND) sValue;
                Element sValueCGAND = doc.createElement("SValueCGAND");

                serializeObject(valueCGAND.getMHat_h(), "mHat_h", sValueCGAND);
                serializeObject(valueCGAND.getRHat(), "rHat", sValueCGAND);

                value.appendChild(sValueCGAND);
            } else if (sValue instanceof SValuesCGNOT) {
                value.setAttribute("type", "SValueCGNOT");
                SValuesCGNOT valueCGNOT = (SValuesCGNOT) sValue;
                Element sValueCGNOT = doc.createElement("SValueCGNOT");

                serializeObject(valueCGNOT.getAHat(), "aHat", sValueCGNOT);
                serializeObject(valueCGNOT.getBHat(), "bHat", sValueCGNOT);
                serializeObject(valueCGNOT.getRHatPrime(), "rHatPrime",
                        sValueCGNOT);

                value.appendChild(sValueCGNOT);
            } else if (sValue instanceof SValuesCGOR) {
                value.setAttribute("type", "SValueCGOR");
                SValuesCGOR valueCGOR = (SValuesCGOR) sValue;
                Element sValueCGOR = doc.createElement("SValueCGOR");

                serializeObject(valueCGOR.getMHat_i(), "mHat_i", sValueCGOR);
                serializeObject(valueCGOR.getAlphaHat(), "alphaHat", sValueCGOR);
                serializeObject(valueCGOR.getBetaHat(), "betaHat", sValueCGOR);
                serializeObject(valueCGOR.getRHat_0(), "rHat_0", sValueCGOR);
                serializeObject(valueCGOR.getRHat_1(), "rHat_1", sValueCGOR);
                serializeObject(valueCGOR.getRHat_2(), "rHat_2", sValueCGOR);

                // TODO (pbi) add the values for the additional commitment

                value.appendChild(sValueCGOR);
            } else {
                throw new RuntimeException("SValue not implemented!");
            }
            values.appendChild(value);
        }
        root.appendChild(values);

        Element verifiableEncryptions = doc
                .createElement("VerifiableEncryptions");
        TreeMap<String, VerifiableEncryption> verEncs = proof.getVerEncs();
        iterator = verEncs.keySet().iterator();

        while (iterator.hasNext()) {
            String key = iterator.next();
            Element verifiableEncryption = doc
                    .createElement("VerifiableEncryption");
            verifiableEncryption.setAttribute("key", key);

            VerifiableEncryption enc = verEncs.get(key);

            doc = serializeVerifiableEncryptionElements(enc,
                    verifiableEncryption);

            verifiableEncryptions.appendChild(verifiableEncryption);
        }
        root.appendChild(verifiableEncryptions);

        return doc;
    }

    private final Document serializeNonce(BigInteger nonce) {
        Element root = doc.createElement("IdmxNonce");
        setRootAttributes(root);
        doc.appendChild(root);

        serializeObject(nonce, "Value", root);

        return doc;
    }

    private final Document serializeIssuerUpdateInformation(
            IssuerUpdateInformation issuerUpdateInfo) {

        Element root = doc.createElement("IssuerUpdateInformation");
        setRootAttributes(root);
        doc.appendChild(root);

        Element element = null, subelement = null;
        Text text = null;

        element = doc.createElement("Location");
        serializeObject(issuerUpdateInfo.getIssuerPublicKeyId(),
                "IssuerPublicKey", element);
        serializeObject(issuerUpdateInfo.getCredStructLocation(),
                "CredentialStructure", element);

        serializeObject(issuerUpdateInfo.getUpdateLocation(), "Update", element);

        root.appendChild(element);

        Iterator<String> it = issuerUpdateInfo.getValues().iterator();
        element = doc.createElement("Values");
        while (it.hasNext()) {
            String name = it.next();
            BigInteger value = issuerUpdateInfo.getValue(name);

            subelement = doc.createElement("Value");
            subelement.setAttribute("name", name);
            text = doc.createTextNode(value.toString());
            subelement.appendChild(text);
            element.appendChild(subelement);
        }
        root.appendChild(element);

        serializeObject(issuerUpdateInfo.getCapQ(), "Q", root);
        serializeObject(issuerUpdateInfo.getVPrimePrime(), "vPrimePrime", root);
        serializeObject(issuerUpdateInfo.getNonce(), "Nonce", root);
        serializeObject(issuerUpdateInfo.getContext(), "Context", root);

        return doc;
    }

    private final Document serializeMessage(Message message) {

        Element root = doc.createElement("Message");
        setRootAttributes(root);
        doc.appendChild(root);

        Element element = null, subelement = null;
        Text text = null;

        Iterator<IssuanceProtocolValues> it = message.iterator();
        element = doc.createElement("Values");
        while (it.hasNext()) {
            IssuanceProtocolValues issuanceProtocolValue = it.next();
            BigInteger value = message
                    .getIssuanceElement(issuanceProtocolValue);

            subelement = doc.createElement("Value");
            subelement.setAttribute("name", issuanceProtocolValue.toString());
            text = doc.createTextNode(value.toString());
            subelement.appendChild(text);
            element.appendChild(subelement);
        }
        root.appendChild(element);

        Proof proof = message.getProof();
        if(proof != null) { /*Modification by USIEGEN to support messag0"*/
        	element = doc.createElement("IdmxProof");
        	serializeProofElements(proof, element);
        	root.appendChild(element);
        }/*Mod end*/

        URI updateLocation = message.getUpdateLocation();
        if (updateLocation != null) {
            serializeObject(updateLocation, "UpdateLocation", root);
        }

        return doc;
    }

    private final Document serializeVerifiableEncryption(
            VerifiableEncryption verifiableEncryption) {

        Element root = doc.createElement("VerifiableEncryption");
        setRootAttributes(root);
        doc.appendChild(root);

        return serializeVerifiableEncryptionElements(verifiableEncryption, root);
    }

    private final Document serializeVerifiableEncryptionElements(
            VerifiableEncryption verifiableEncryption, Element root) {

        Element element = doc.createElement("Locations");
        serializeObject(verifiableEncryption.getVEPublicKeyLocation(),
                "VEPublicKeyLocation", element);
        root.appendChild(element);

        element = doc.createElement("Elements");

        serializeObject(verifiableEncryption.getCapL(), "Label", element);
        serializeObject(verifiableEncryption.getU(), "u", element);
        serializeObject(verifiableEncryption.getE(), "e", element);
        serializeObject(verifiableEncryption.getV(), "v", element);

        root.appendChild(element);

        return doc;
    }

    private final Document serializeVerifiableEncryptionOpening(
            VerifiableEncryptionOpening verifiableEncryptionOpening) {

        Element root = doc.createElement("VerifiableEncryptionOpening");
        setRootAttributes(root);
        doc.appendChild(root);

        Element element = doc.createElement("Locations");
        serializeObject(verifiableEncryptionOpening.getVEPublicKeyLocation(),
                "VEPublicKeyLocation", element);
        root.appendChild(element);

        element = doc.createElement("Elements");

        serializeObject(verifiableEncryptionOpening.getMessage(), "Message",
                element);
        serializeObject(verifiableEncryptionOpening.getR(), "r", element);
        serializeObject(verifiableEncryptionOpening.getCapL(), "Label", element);

        root.appendChild(element);

        return doc;
    }
}
