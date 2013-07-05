/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.idmx.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.DomNym;
import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.dm.Nym;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.DataType;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.dm.structure.PrimeEncodingFactor;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zurich.idmx.issuance.update.UpdateSpecification;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPrivateKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.showproof.Identifier.ProofMode;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.ip.InequalityProver;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.CommitmentPredicate;
import com.ibm.zurich.idmx.showproof.predicates.DomainNymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate.InequalityOperator;
import com.ibm.zurich.idmx.showproof.predicates.MessagePredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate.PrimeEncodeOp;
import com.ibm.zurich.idmx.showproof.predicates.PseudonymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.RepresentationPredicate;
import com.ibm.zurich.idmx.showproof.predicates.VerEncPredicate;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGAND;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGNOT;
import com.ibm.zurich.idmx.showproof.sval.SValuesCGOR;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.showproof.sval.SValuesProveCL;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;
import com.ibm.zurich.idmx.ve.VerifiableEncryptionOpening;

/**
 * Parsing class, which allows to load XML files specifying things such as
 * issuer keys, credential structures or proof specifications.
 */
public class Parser {

    /** Logger. */
    private static Logger log = Logger.getLogger(Parser.class.getName());

    /** Singleton design pattern. */
    private static Parser parser;

    protected DocumentBuilder db;
    /** Make document available to extending classes. */
    protected Document document;

    private HashMap<Identifier, String[]> identifierToAttributeMap = new HashMap<Identifier, String[]>();

    /**
     * Constructor.
     */
    protected Parser() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // dbf.setValidating(true);
        dbf.setIgnoringComments(true);
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setNamespaceAware(true);

        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
    }

    /**
     * Singleton design pattern.
     * 
     * @return Parser object.
     */
    public static Parser getInstance() {
        if (parser == null) {
            parser = new Parser();
        }
        return parser;
    }

    /**
     * Method for validation of XML Document against XML Schema.
     * 
     * @param xmlFilename
     *            Name of the file with XML Document.
     * @param xsdFilename
     *            Name of the file with XML Schema.
     * @return True if validation succeeds.
     */
    public boolean validate(String xmlFilename, String xsdFilename) {
        SchemaFactory factory = SchemaFactory
                .newInstance("http://www.w3.org/2001/XMLSchema");
        File schemaLocation = new File(xsdFilename);

        try {
            Schema schema = factory.newSchema(schemaLocation);
            Validator validator = schema.newValidator();

            Document document = db.parse(new File(xmlFilename));

            DOMSource source = new DOMSource(document);
            DOMResult result = new DOMResult();

            validator.validate(source, result);
            // Document augmented = (Document) result.getNode();
            // do whatever you need to do with the augmented document...
        } catch (Exception e) {
            System.out.println("Validation of " + xmlFilename
                    + " using schema " + xsdFilename + " failed.");
            e.printStackTrace();
        }

        return true;
    }

    /**
     * In the following example, <i>ValUe</i> would be returned. Note, that tabs
     * and newline characters will be removed.
     * 
     * <pre>
     * &lt;root&gt; 
     *    &lt;name&gt;
     *       ValUe
     *    &lt;/name&gt;
     * &lt;/root&gt;
     * </pre>
     * 
     * @param root
     *            Root element of the references section.
     * @param name
     *            Name of the element that should be retrieved.
     * @return URI of the group parameters.
     */
    protected final static String getValue(final Element root, final String name) {
        NodeList node = root.getElementsByTagName(name);
        return getValue(node.item(0));
    }

    /**
     * In the following example, <i>ValUe</i> would be returned. Note, that tabs
     * and newline characters will be removed.
     * 
     * <pre>
     * &lt;root&gt; 
     *    &lt;name&gt;
     *       ValUe
     *    &lt;/name&gt;
     * &lt;/root&gt;
     * </pre>
     * 
     * @param root
     *            Root element of the references section.
     * @param name
     *            Name of the element that should be retrieved.
     * @return URI of the group parameters.
     */
    protected URI getURIValue(final Element root, final String name) {
        try {
            return new URI(getValue(root, name));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * In the following example, <i>ValUe</i> would be returned. Note, that tabs
     * and newline characters will be removed.
     * 
     * <pre>
     * &lt;node&gt; 
     *    ValUe
     * &lt;/node&gt;
     * </pre>
     * 
     * @param node
     *            Node who's value should be retrieved.
     * @return URI of the group parameters.
     */
    protected URI getURIValue(final Node node) {
        try {
            return new URI(getValue(node));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * In the following example, <i>ValUe</i> would be returned. Note, that tabs
     * and newline characters will be removed.
     * 
     * <pre>
     * &lt;node&gt; 
     *    ValUe
     * &lt;/node&gt;
     * </pre>
     * 
     * @param node
     *            Node who's value should be retrieved.
     * @return Value of the given node.
     */
    protected final static String getValue(final Node node) {
        return normalize(node.getFirstChild().getNodeValue());
    }

    /**
     * Removes tab and newline characters from its input.
     * 
     * @param string
     *            String, which might contain tab/newline characters.
     * @return String without the tab and newline characters.
     */
    private final static String normalize(final String string) {
        String value = string.replaceAll("\\n", "");
        value = value.replaceAll("\\t", "");
        return value;
    }

    /**
     * Removes tab and newline characters from its input.
     * 
     * @param string
     *            String, which might contain tab/newline characters.
     * @return String without the tab and newline characters.
     */
    private final static String normalizeMessage(final String string) {
        String value = string.replaceAll("\\n", " ");
        value = value.replaceAll("\\t", "");
        return value;
    }

    /**
     * Given a named node map, it returns the attribute named <code>name</code>.
     * Note, that tabs and newline characters will be removed.
     * 
     * @param attributeMap
     *            NamedNodeMap containing all the attributes of an element.
     * @param name
     *            Name of the attribute that should be retrieved.
     * @return Attribute called <code>name</code>.
     */
    protected final static String getAttribute(final NamedNodeMap attributeMap,
            final String name) {
        return normalize(attributeMap.getNamedItem(name).getNodeValue());
    }

    /**
     * Given a named node map, it returns the attribute named <code>name</code>.
     * Note, that tabs and newline characters will be removed.
     * 
     * @param attributeMap
     *            NamedNodeMap containing all the attributes of an element.
     * @param name
     *            Name of the attribute that should be retrieved.
     * @return Attribute called <code>name</code>.
     */
    private final static URI getURIAttribute(final NamedNodeMap attributeMap,
            final String name) {
        try {
            return new URI(normalize(attributeMap.getNamedItem(name)
                    .getNodeValue()));
        } catch (DOMException e) {
            e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param uri
     *            URI of the data that should be parsed.
     * @return Parsed object.
     * @see #parse(InputSource)
     */
    public final Object parse(URI uri) {
    	// TODO (frp): Check setting the connection timeout and/or whether http url does not exist.
        try {
        	InputStream inputStream = uri.toURL().openStream();
        	InputSource inputSource = new InputSource(inputStream);
        	Object result = parse(inputSource);
        	inputStream.close();
        	return result;
        	
		} catch (IOException e1) {
			log.log(Level.SEVERE, "Cannot read from file: " + uri.toString() + ".");
			return null;
		}
// TODO (frp): sync with Patrik!    	
//    	
//    	
//        InputSource inputSource = null;
//        InputStream inputStream = null;
//        
//        try {
//            if (uri.getScheme().equalsIgnoreCase("file")) {
//                inputStream = new FileInputStream(uri.getPath());
//                inputSource = new InputSource(inputStream);
//            } else if (uri.getScheme().equalsIgnoreCase("http")) {
//                URLConnection connection = uri.toURL().openConnection();
//                connection.setConnectTimeout(1000);
//                try {
//                    inputStream = connection.getInputStream();
//                } catch (SocketTimeoutException e) {
//                    log.log(Level.SEVERE, "Connection cannot be opened. The "
//                            + "element with the following URI cannot be "
//                            + "loaded: " + uri.toString());
//
//                }
//                inputSource = new InputSource(inputStream);
//            } else {
//                throw new RuntimeException("Scheme: " + uri.getScheme()
//                        + " not supported.");
//            }
//        } catch (FileNotFoundException e) {
//            log.log(Level.SEVERE, "File: " + uri.toString() + " not found.");
//        } catch (MalformedURLException e) {
//            log.log(Level.SEVERE, "File: " + uri.toString() + " not found.");
//        } catch (IOException e) {
//            log.log(Level.SEVERE, "File: " + uri.toString() + " not found.");
//        }
//
//        if (inputSource == null) {
//            return null;
//        }
//        Object result = parse(inputSource);
//        try {
//            inputStream.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return result;
    }

    /**
     * Parses a string representing the object to be parsed. Note, that the
     * string does not locate a file with the contents to be parsed as this
     * functionality is offered by <code>parse(URI)</code>.
     * 
     * @param objectAsString
     *            String to be parsed.
     * @return Object that was represented in the string.
     */
    public final Object parse(String objectAsString) {
        InputSource is = new InputSource();
        is.setCharacterStream(new StringReader(objectAsString));
        return parse(is);
    }

    /**
     * @param inputSource
     *            Input source containing the XML that is to be parsed.
     * @return Element of the type as specified in the given XML file.
     */
    public Object parse(final InputSource inputSource) {
        String rootName = "";
        try {
            // parse document
            document = db.parse(inputSource);
            document.normalize();

            // load top level element to extract the schema for validation
            Element documentElement = document.getDocumentElement();
            // String xmlns_xs = documentElement.getAttribute("xmlns:xs");
            // String[] schemaLocation = documentElement.getAttribute(
            // "xsi:schemaLocation").split(" ", 2);
            //
            // // validate the given XML using the indicated XSD
            // SchemaFactory factory = SchemaFactory.newInstance(xmlns_xs);
            // // TODO (pbi): use the URI in schemaLocation[0]
            // Schema schema = factory.newSchema(new File(schemaLocation[1]));
            // Validator validator = schema.newValidator();
            //
            // // validate the DOM tree
            // try {
            // validator.validate(new DOMSource(document));
            // } catch (SAXException e) {
            // log.log(Level.SEVERE,
            // "XML is not a valid document according to "
            // + schemaLocation[1]);
            // }

            // Identify appropriate parsing strategy (by inspection of the root
            // element)
            rootName = documentElement.getNodeName();
            if (rootName.equalsIgnoreCase("ProofSpecification")) {
                return parseProofSpec(document);

            } else if (rootName.equalsIgnoreCase("CredentialStructure")) {
                return parseCredentialStructure(document);

            } else if (rootName.equalsIgnoreCase("Credential")) {
                return parseCredential(document);

            } else if (rootName.equalsIgnoreCase("IssuerPublicKey")) {
                return parseIssuerPublicKey(document);

            } else if (rootName.equalsIgnoreCase("IssuerPrivateKey")) {
                return parseIssuerSecretKey(document);

            } else if (rootName.equalsIgnoreCase("MasterSecret")) {
                return parseMasterSecret(document);

            } else if (rootName.equalsIgnoreCase("GroupParameters")) {
                return parseGroupParameters(document);

            } else if (rootName.equalsIgnoreCase("SystemParameters")) {
                return parseSystemParameters(document);

            } else if (rootName
                    .equalsIgnoreCase("VerifiableEncryptionPrivateKey")) {
                return parseVerEncSecretKey(document);

            } else if (rootName
                    .equalsIgnoreCase("VerifiableEncryptionPublicKey")) {
                return parseVerEncPublicKey(document);

            } else if (rootName.equalsIgnoreCase("IdmxProof")) {
                return parseProof(document);

            } else if (rootName.equalsIgnoreCase("IdmxNonce")) {
                return parseNonce(document);

            } else if (rootName.equalsIgnoreCase("UpdateSpecification")) {
                return parseUpdateSpecification(document);

            } else if (rootName.equalsIgnoreCase("IssuerUpdateInformation")) {
                return parseIssuerUpdateInformation(document);

            } else if (rootName.equalsIgnoreCase("Message")) {
                return parseMessage(document);

            } else if (rootName.equalsIgnoreCase("VerifiableEncryption")) {
                return parseVerifiableEncryption((Element) document
                        .getElementsByTagName("VerifiableEncryption").item(0));

            } else if (rootName.equalsIgnoreCase("VerifiableEncryptionOpening")) {
                return parseVerifiableEncryptionOpening(document);

            }

        } catch (IOException e) {
            log.log(Level.SEVERE, "IOException::Error parsing element "
                    + rootName + ": " + e.getMessage());
        } catch (SAXException e) {
            log.log(Level.SEVERE, "SAXExcepton::Error parsing element "
                    + rootName + ": " + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.log(Level.SEVERE,
                    "IllegalArgumentException::Error parsing element "
                            + rootName + ": " + e.getMessage());
        }
        return null;
    }

    /**
     * @param document
     *            Root of the document.
     * @return Proof specification.
     */
    private final Object parseProofSpec(final Document document) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        Element specification = (Element) document.getElementsByTagName(
                "Specification").item(0);

        HashMap<String, Identifier> identifierMap;

        // Parse AttributeIds
        Element declarations = (Element) document.getElementsByTagName(
                "Declaration").item(0);
        identifierMap = parseAttributeIdentifiers(declarations);

        // Parse credentials
        NodeList credentials = ((Element) specification.getElementsByTagName(
                "Credentials").item(0)).getElementsByTagName("Credential");
        predicates.addAll(parseCredentials(credentials, identifierMap));

        // Parse enum attributes
        NodeList enumAttributes = ((Element) specification
                .getElementsByTagName("EnumAttributes").item(0))
                .getElementsByTagName("EnumAttribute");
        predicates.addAll(parseEnumAttributes(enumAttributes, identifierMap));

        // Parse inequalities
        NodeList inequalities = ((Element) specification.getElementsByTagName(
                "Inequalities").item(0)).getElementsByTagName("Inequality");
        predicates.addAll(parseInequalities(inequalities, identifierMap));

        // Parse Commitments
        NodeList commitments = ((Element) specification.getElementsByTagName(
                "Commitments").item(0)).getElementsByTagName("Commitment");
        predicates.addAll(parseCommitments(commitments, identifierMap));

        // Parse Representations
        NodeList representations = ((Element) specification
                .getElementsByTagName("Representations").item(0))
                .getElementsByTagName("Representation");
        predicates.addAll(parseRepresentations(representations, identifierMap));

        // Parse Pseudonyms
        Element pseudonyms = (Element) specification.getElementsByTagName(
                "Pseudonyms").item(0);
        predicates.addAll(parsePseudonyms(pseudonyms));

        // Parse VerifiableEncryptions
        NodeList verifiableEncryptions = ((Element) specification
                .getElementsByTagName("VerifiableEncryptions").item(0))
                .getElementsByTagName("VerifiableEncryption");
        predicates.addAll(parseVerEncs(verifiableEncryptions, identifierMap));

        // Parse Messages
        NodeList messages = ((Element) specification.getElementsByTagName(
                "Messages").item(0)).getElementsByTagName("Message");
        predicates.addAll(parseMessages(messages));

        // Error cases..
        // - we allow empty identifier maps as there might be credentials
        // without attributes

        // Create new proof specification
        return new ProofSpec(identifierMap, predicates);
    }

    /**
     * @param declarations
     *            Root of the declarations element.
     * @return Map of the names of identifiers to identifiers. Those names will
     *         be used to refer to identifiers throughout the document.
     */
    private final HashMap<String, Identifier> parseAttributeIdentifiers(
            final Element declarations) {
        HashMap<String, Identifier> identifierMap;
        identifierMap = new HashMap<String, Identifier>();

        NodeList attributeIds = declarations
                .getElementsByTagName("AttributeId");
        for (int i = 0; i < attributeIds.getLength(); i++) {
            NamedNodeMap atts = attributeIds.item(i).getAttributes();
            String identifierName = getAttribute(atts, "name");
            ProofMode proofMode = ProofMode.valueOf(getAttribute(atts,
                    "proofMode").toUpperCase());
            DataType dataType = DataType.valueOf(getAttribute(atts, "type")
                    .toUpperCase());
            Identifier id = new Identifier(identifierName, dataType, proofMode);

            // verify that attribute identifier have unique names
            if (identifierMap.keySet().contains(identifierName)) {
                throw new RuntimeException("[Parser:"
                        + "parseAttributeIdentifiers()] Identifiers must "
                        + "have unique names.");
            }
            identifierMap.put(identifierName, id);
        }
        return identifierMap;
    }

    /**
     * @param enumAttributes
     *            Root of the enumeration attributes section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return Enumeration predicates.
     */
    private final Vector<Predicate> parseEnumAttributes(
            final NodeList enumAttributes,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < enumAttributes.getLength(); i++) {
            Node enumAttribute = enumAttributes.item(i);
            String idName = getAttribute(enumAttribute.getAttributes(),
                    "attributeId");
            String opName = getAttribute(enumAttribute.getAttributes(),
                    "operator").toUpperCase();
            Identifier identifier = identifierMap.get(idName);
            if (identifier == null) {
                throw new RuntimeException("Identifier: " + idName
                        + " not found.");
            }
            String[] attributeIdentifier = identifierToAttributeMap
                    .get(identifier);
            identifier.setAttributeName(attributeIdentifier[0], attributeIdentifier[1],
                    attributeIdentifier[2]);

            PrimeEncodeOp operator = PrimeEncodeOp.valueOf(opName);
            String predName = idName + Constants.DELIMITER + opName;

            Vector<String> enumValueMap = new Vector<String>();
            NodeList enumValues = ((Element) enumAttribute)
                    .getElementsByTagName("EnumValue");
            for (int k = 0; k < enumValues.getLength(); k++) {
                Node enumValue = enumValues.item(k);
                String attName = getAttribute(enumValue.getAttributes(),
                        "attributeName");
                String value = getValue(enumValue);

                enumValueMap.add(attName + Constants.DELIMITER + value);
            }

            boolean sameIdentifierOperator = false;
            for (Predicate pred : predicates) {
                if (pred instanceof PrimeEncodePredicate) {
                    PrimeEncodePredicate pePred = ((PrimeEncodePredicate) pred);
                    if (pePred.getName().equals(predName)) {
                        pePred.addAttributeNames(enumValueMap);
                        sameIdentifierOperator = true;
                        break;
                    }
                }
            }

            if (!sameIdentifierOperator) {
                PrimeEncodePredicate pred = new PrimeEncodePredicate(predName,
                        identifier, enumValueMap, operator);
                predicates.add(pred);
            }
        }
        return predicates;
    }

    /**
     * @param credentials
     *            Root of the credentials section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return CLPredicates.
     */
    private final Vector<Predicate> parseCredentials(
            final NodeList credentials,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < credentials.getLength(); i++) {
            Node credential = credentials.item(i);
            String credName = getAttribute(credential.getAttributes(), "name");
            URI credStructLocation = null, ipkId = null;

            ipkId = getURIAttribute(credential.getAttributes(),
                    "issuerPublicKey");
            credStructLocation = getURIAttribute(credential.getAttributes(),
                    "credStruct");

            HashMap<String, Identifier> attToIdentifierMap = new HashMap<String, Identifier>();

            NodeList attributes = ((Element) credential)
                    .getElementsByTagName("Attribute");
            for (int k = 0; k < attributes.getLength(); k++) {
                Node attribute = attributes.item(k);
                String attName = getAttribute(attribute.getAttributes(), "name");

                Identifier attId = identifierMap.get(getValue(attribute));
                if (attId == null) {
                    throw new RuntimeException("Identifier: "
                            + getValue(attribute) + " not found.");
                }
                attToIdentifierMap.put(attName, attId);
                // this is required for the Prime Encoded Values
                String[] attributeIdentifier = new String[3];
                attributeIdentifier[0] = ipkId.toString();
                attributeIdentifier[1] = credStructLocation.toString();
                attributeIdentifier[2] = attName;
                identifierToAttributeMap.put(attId, attributeIdentifier);
            }

            CLPredicate pred = new CLPredicate(ipkId, credStructLocation,
                    credName, attToIdentifierMap);

            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param inequalities
     *            Root of the Inequalities section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return Inequality predicate.
     */
    private final Vector<Predicate> parseInequalities(
            final NodeList inequalities,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();
        for (int i = 0; i < inequalities.getLength(); i++) {
            Node inequality = inequalities.item(i);

            NamedNodeMap inequalityAtts = inequality.getAttributes();
            String operator = getAttribute(inequalityAtts, "operator")
                    .toUpperCase();
            String secondArgument = getAttribute(inequalityAtts,
                    "secondArgument");
            URI key = null;

            key = getURIAttribute(inequalityAtts, "publicKey");

            Identifier identifier = identifierMap.get(getValue(inequality));
            if (identifier == null) {
                throw new RuntimeException("Identifier: "
                        + getValue(inequality) + " not found.");
            }
            String predName = identifier.getName() + Constants.DELIMITER
                    + operator + Constants.DELIMITER + secondArgument;

            InequalityPredicate pred;
            Identifier secondArg = identifierMap.get(secondArgument);
            if (secondArg != null) {
                if (secondArg.isRevealed()) {
                    pred = new InequalityPredicate(predName, key, identifier,
                            InequalityOperator.valueOf(operator), secondArg);
                } else {
                    throw new RuntimeException("Malformed proof "
                            + "specification: Inequality proofs can only "
                            + "be created w.r.t. reveled arguments but "
                            + "identifier: " + secondArgument + " is not "
                            + "revealed.");
                }
            } else {
                BigInteger secondValue;
                if (secondArgument.equalsIgnoreCase("CURRENT_EPOCH")) {
                    secondValue = ((IssuerPublicKey) StructureStore
                            .getInstance().get(key)).computeCurrentEpoch();
                } else {
                    secondValue = new BigInteger(secondArgument);
                }
                pred = new InequalityPredicate(predName, key, identifier,
                        InequalityOperator.valueOf(operator), secondValue);
            }

            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param commitments
     *            Root of the commitments section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return Commitment predicate.
     */
    private final Vector<Predicate> parseCommitments(
            final NodeList commitments,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < commitments.getLength(); i++) {
            Node commitment = commitments.item(i);

            String commName = getAttribute(commitment.getAttributes(), "name");

            NodeList exponents = ((Element) commitment)
                    .getElementsByTagName("Exponent");
            Vector<Identifier> identifiers = new Vector<Identifier>(
                    exponents.getLength());
            for (int k = 0; k < exponents.getLength(); k++) {
                Node exponent = exponents.item(k);
                int index = Integer.parseInt(getAttribute(
                        exponent.getAttributes(), "index"));

                Identifier identifier = identifierMap.get(getValue(exponent));
                if (identifier == null) {
                    throw new RuntimeException("Identifier: "
                            + getValue(exponent) + " not found.");
                }
                identifiers.add(index, identifier);
            }

            CommitmentPredicate pred = new CommitmentPredicate(commName,
                    identifiers);
            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param representations
     *            Root of the representation section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return Representation predicate.
     */
    private final Vector<Predicate> parseRepresentations(
            final NodeList representations,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < representations.getLength(); i++) {
            Node representation = representations.item(i);

            String name = getAttribute(representation.getAttributes(), "name");

            NodeList elements = ((Element) representation)
                    .getElementsByTagName("Exponent");
            int length = elements.getLength();
            Vector<Identifier> identifiers = new Vector<Identifier>(length);
            Vector<BigInteger> bases = new Vector<BigInteger>(length);
            for (int k = 0; k < length; k++) {
                Node exponent = elements.item(k);
                BigInteger base = new BigInteger(getAttribute(
                        exponent.getAttributes(), "base"));
                int index = Integer.parseInt(getAttribute(
                        exponent.getAttributes(), "index"));

                Identifier identifier = identifierMap.get(getValue(exponent));
                if (identifier == null) {
                    throw new RuntimeException("Identifier: "
                            + getValue(exponent) + " not found.");
                }
                identifiers.add(index, identifier);
                bases.add(base);
            }

            RepresentationPredicate pred = new RepresentationPredicate(name,
                    identifiers, bases);
            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param pseudonyms
     *            Root of the pseudonyms section.
     * @return Pseudonym predicates.
     */
    private final Vector<Predicate> parsePseudonyms(final Element pseudonyms) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        // Parse domain pseudonyms (domNyms)
        NodeList domainPseudonyms = pseudonyms
                .getElementsByTagName("DomainPseudonym");
        for (int i = 0; i < domainPseudonyms.getLength(); i++) {
            String domain = getValue(domainPseudonyms.item(i));
            if (domain.equalsIgnoreCase("")) {
                throw new RuntimeException("Domain must not be empty in the "
                        + i + "-th domain pseudonym.");
            }
            predicates.add(new DomainNymPredicate(domain));
        }

        // Parse regular peudonyms (nyms)
        NodeList nyms = pseudonyms.getElementsByTagName("Pseudonym");
        for (int i = 0; i < nyms.getLength(); i++) {
            String tempNymName = getAttribute(nyms.item(i).getAttributes(),
                    "name");
            predicates.add(new PseudonymPredicate(tempNymName));
        }

        return predicates;
    }

    /**
     * @param verifiableEncryptions
     *            Root of the verifiable encryptions section.
     * @param identifierMap
     *            Map of identifier names to identifiers.
     * @return Verifiable encryption predicate.
     */
    private final Vector<Predicate> parseVerEncs(
            final NodeList verifiableEncryptions,
            final HashMap<String, Identifier> identifierMap) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < verifiableEncryptions.getLength(); i++) {
            Node verifiableEncryption = verifiableEncryptions.item(i);
            NamedNodeMap verEncAtts = verifiableEncryption.getAttributes();
            String name = getAttribute(verEncAtts, "name");
            URI key = getURIAttribute(verEncAtts, "publicKey");
            String label = getAttribute(verEncAtts, "label");
            Identifier identifier = identifierMap
                    .get(getValue(verifiableEncryption));
            if (identifier == null) {
                throw new RuntimeException("Identifier: "
                        + getValue(verifiableEncryption) + " not found.");
            }
            VerEncPredicate pred = new VerEncPredicate(name, identifier, key,
                    label);
            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param messages
     *            Root of the messages section.
     * @return Message predicate.
     */
    private final Vector<Predicate> parseMessages(final NodeList messages) {
        Vector<Predicate> predicates = new Vector<Predicate>();

        for (int i = 0; i < messages.getLength(); i++) {
            Node message = messages.item(i);
            String name = getAttribute(message.getAttributes(), "name");
            String messageValue = normalizeMessage(message.getFirstChild()
                    .getNodeValue());

            MessagePredicate pred = new MessagePredicate(name, messageValue);
            predicates.add(pred);
        }
        return predicates;
    }

    /**
     * @param document
     *            Root of the document.
     * @return Credential structure.
     */
    private final Object parseCredentialStructure(final Document document) {
        // // TODO (pbi/frp) there should be a reference to the issuer public
        // key
        // // in the credential! Then, this reference can be removed.
        // Element references = (Element) document.getElementsByTagName(
        // "References").item(0);
        // // Parse references
        // URI issuerPublicKeyName = getURIValue(references, "IssuerPublicKey");

        // Parse attributes
        Element attributes = (Element) document.getElementsByTagName(
                "Attributes").item(0);

        // Parse features
        Element features = (Element) document.getElementsByTagName("Features")
                .item(0);
        HashMap<String, String> featureInformation = parseFeatures(features);

        // Parse implementation specifics
        Element implementation = (Element) document.getElementsByTagName(
                "Implementation").item(0);
        Vector<AttributeStructure> attStructures = parseAttributes(attributes,
                implementation);

        return new CredentialStructure(attStructures, featureInformation);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Credential.
     */
    private final Object parseCredential(final Document document) {

        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI credStructId = getURIValue(references, "CredentialStructure");
        URI ipkId = getURIValue(references, "IssuerPublicKey");

        CredentialStructure cs = (CredentialStructure) StructureStore
                .getInstance().get(credStructId);

        Element attributeValues = (Element) document.getElementsByTagName(
                "Attributes").item(0);
        Vector<Attribute> attributes = parseCredentialAttributes(
                attributeValues, cs);

        Element signature = (Element) document
                .getElementsByTagName("Signature").item(0);

        BigInteger capA = new BigInteger(getValue(signature, "A"));
        BigInteger e = new BigInteger(getValue(signature, "e"));
        BigInteger v = new BigInteger(getValue(signature, "v"));

        Element features = (Element) document.getElementsByTagName("Features")
                .item(0);

        Credential cred = new Credential(ipkId, credStructId, capA, e, v,
                attributes);

        if (features != null) {
            Element updates = (Element) features
                    .getElementsByTagName("Updates").item(0);

            if (updates != null) {
                URI updateLocation = getURIValue(updates, "UpdateSpecification");
                BigInteger capU = new BigInteger(getValue(updates, "capU"));
                BigInteger vPrime = new BigInteger(getValue(updates, "vPrime"));
                BigInteger nonce = new BigInteger(getValue(updates, "nonce"));
                BigInteger context = new BigInteger(
                        getValue(updates, "context"));

                cred.new UpdateInformation(capU, vPrime, updateLocation, nonce,
                        context);
            }
        }

        return cred;
    }

    /**
     * @param bases
     *            Root of the commitment bases section.
     * @return Commitment bases.
     */
    private final Vector<BigInteger> parseCommitmentBases(Element bases) {
        Vector<BigInteger> basesValues = new Vector<BigInteger>();
        BigInteger base = null;

        NodeList nodes = bases.getElementsByTagName("Base");

        for (int i = 0; i < nodes.getLength(); ++i) {
            Node node = nodes.item(i);
            // String nodeName = node.getFirstChild().getNodeName();
            String value = node.getFirstChild().getNodeValue();

            base = new BigInteger(value);
            basesValues.add(base);
        }
        return basesValues;
    }

    /**
     * @param messages
     *            Root of the commitment messages section.
     * @return Commitment messages.
     */
    private final Vector<BigInteger> parseCommitmentMessages(Element messages) {
        Vector<BigInteger> messageValues = new Vector<BigInteger>();

        NodeList nodes = messages.getElementsByTagName("Message");

        for (int i = 0; i < nodes.getLength(); ++i) {
            Node node = nodes.item(i);
            String value = node.getFirstChild().getNodeValue();

            messageValues.add(new BigInteger(value));
        }

        return messageValues;
    }

    /**
     * @param commitment
     *            Root of the commitment section.
     * @return Commitment.
     */
    private final Commitment parseCredentialCommitment(final Element commitment) {
        NodeList nodes = commitment.getChildNodes();

        BigInteger val = null;
        BigInteger capS = null;
        BigInteger n = null;
        Vector<BigInteger> bases = null;
        Vector<BigInteger> messages = null;
        BigInteger rand = null;

        for (int i = 0; i < nodes.getLength(); ++i) {
            Node node = nodes.item(i);
            String nodeName = node.getNodeName();

            if (nodeName.equals("commitment")) {
                val = new BigInteger(node.getFirstChild().getNodeValue());
            } else if (nodeName.equals("S")) {
                capS = new BigInteger(node.getFirstChild().getNodeValue());
            } else if (nodeName.equals("n")) {
                n = new BigInteger(node.getFirstChild().getNodeValue());
            } else if (nodeName.equals("Bases")) {
                bases = parseCommitmentBases((Element) node);
            } else if (nodeName.equals("CommitmentOpening")) {
                Element messageValues = (Element) commitment
                        .getElementsByTagName("Messages").item(0);
                messages = parseCommitmentMessages(messageValues);

                Element randValue = (Element) commitment.getElementsByTagName(
                        "rand").item(0);
                String value = randValue.getFirstChild().getNodeValue();
                rand = new BigInteger(value);
            }
        }

        return new CommitmentOpening(val, bases, capS, n, messages, rand);
    }

    /**
     * @param attributeValues
     *            Root of the attributes section.
     * @param credentialStructure
     *            Credential structure used for attributes creation.
     * @return Attributes.
     */
    private final Vector<Attribute> parseCredentialAttributes(
            final Element attributeValues,
            CredentialStructure credentialStructure) {
        Vector<Attribute> attributes = new Vector<Attribute>();

        NodeList attrs = attributeValues.getElementsByTagName("Attribute");

        for (int i = 0; i < attrs.getLength(); ++i) {
            Element attr = (Element) attrs.item(i);
            String attrName = getAttribute(attr.getAttributes(), "name");

            Object value = null;
            HashSet<String> enumValues = new HashSet<String>();

            NodeList nodes = attr.getElementsByTagName("*");

            for (int j = 0; j < nodes.getLength(); ++j) {
                Node node = nodes.item(j);
                String nodeName = node.getNodeName();

                if (nodeName.equals("Value")) {
                    value = new BigInteger(node.getFirstChild().getNodeValue());
                } else if (nodeName.equals("Commitment")) {
                    value = parseCredentialCommitment((Element) node);
                } else if (nodeName.equals("EnumValue")) {
                    enumValues.add(node.getFirstChild().getNodeValue());
                }
            }

            AttributeStructure attrStruct = credentialStructure
                    .getAttributeStructure(attrName);
            Attribute attribute = null;

            if (enumValues.isEmpty()) {
                attribute = new Attribute(attrStruct, value);
            } else {
                attribute = new Attribute(attrStruct, value, enumValues);
            }

            attributes.add(attribute);
        }

        return attributes;
    }

    /**
     * @param features
     *            Parent element of the Features section.
     * @return Map of values contained in the features section.
     */
    private final HashMap<String, String> parseFeatures(final Element features) {
        HashMap<String, String> featureInformation = new HashMap<String, String>();

        NodeList node = features.getElementsByTagName("UpdateSpecification");
        if (node.getLength() > 0) {
            featureInformation.put("updateSpecification",
                    getValue(node.item(0)));
        }
        node = features.getElementsByTagName("Date");
        if (node.getLength() > 0) {
            featureInformation.put("timeZone", getValue(node.item(0)));
        }

        return featureInformation;
    }

    /**
     * @param attributes
     *            Parent element of the Attributes section.
     * @param implementation
     *            Parent element of the Implementation section.
     * @return List of attribute structures of the credential structure.
     */
    private final Vector<AttributeStructure> parseAttributes(
            final Element attributes, final Element implementation) {
        NodeList attribs = attributes.getElementsByTagName("Attribute");
        NodeList attribOrder = ((Element) implementation.getElementsByTagName(
                "AttributeOrder").item(0)).getElementsByTagName("Attribute");
        NodeList primeEncodings = implementation
                .getElementsByTagName("PrimeEncoding");

        int length = attribs.getLength();
        String[] name = new String[length];
        IssuanceMode[] issuanceMode = new IssuanceMode[length];
        DataType[] dataType = new DataType[length];
        int[] publicKeyIndex = new int[length];
        HashMap<String, Integer> nameMap = new HashMap<String, Integer>();

        HashMap<String, PrimeEncodingFactor> primeFactorMap;
        primeFactorMap = new HashMap<String, PrimeEncodingFactor>();

        HashMap<String, HashMap<String, PrimeEncodingFactor>> finalMap;
        finalMap = new HashMap<String, HashMap<String, PrimeEncodingFactor>>();

        // Parsing Attributes
        for (int i = 0; i < length; i++) {
            NamedNodeMap attributeAtts = attribs.item(i).getAttributes();

            String attName = getAttribute(attributeAtts, "name");
            String attributeDataType = getAttribute(attributeAtts, "type")
                    .toUpperCase();
            // scanning enumerated attributes
            if (attributeDataType.equals("ENUM")) {
                NodeList attValues = ((Element) attribs.item(i))
                        .getElementsByTagName("EnumValue");
                for (int j = 0; j < attValues.getLength(); j++) {
                    String attValue = attValues.item(j).getFirstChild()
                            .getNodeValue();
                    String key = attName + Constants.DELIMITER + attValue;
                    primeFactorMap.put(key, new PrimeEncodingFactor(attName,
                            attValue));
                }
            } else {
                dataType[i] = DataType.valueOf(attributeDataType);
            }
            name[i] = attName;
            issuanceMode[i] = IssuanceMode.valueOf(attributeAtts
                    .getNamedItem("issuanceMode").getNodeValue().toUpperCase());
            nameMap.put(name[i], Integer.valueOf(i));
        }

        // Parsing PrimeEncoding
        int[] numValues = new int[name.length];

        length = primeEncodings.getLength();
        for (int i = 0; i < length; i++) {
            HashMap<String, PrimeEncodingFactor> tempMap;
            tempMap = new HashMap<String, PrimeEncodingFactor>();

            HashSet<String> attributeNames = new HashSet<String>();
            NodeList primeFactors = ((Element) primeEncodings.item(i))
                    .getElementsByTagName("PrimeFactor");
            for (int j = 0; j < primeFactors.getLength(); j++) {
                Node primeFactor = primeFactors.item(j);
                NamedNodeMap primeFactorAttributes = primeFactor
                        .getAttributes();
                String attName = getAttribute(primeFactorAttributes, "attName");
                String attValue = getAttribute(primeFactorAttributes,
                        "attValue");
                BigInteger prime = new BigInteger(normalize(primeFactor
                        .getFirstChild().getNodeValue()));
                String key = attName + Constants.DELIMITER + attValue;
                PrimeEncodingFactor primeEncodingFactor = primeFactorMap
                        .get(key);
                primeEncodingFactor.setPrimeFactor(prime);
                tempMap.put(key, primeEncodingFactor);
                // check if this attribute is already in the list of attributes
                if (!attributeNames.contains(attName)) {
                    attributeNames.add(attName);
                }
            }

            // Matching attributes to prime encodings
            Iterator<String> j = attributeNames.iterator();
            IssuanceMode peIssuanceMode = null;
            while (j.hasNext()) {
                String attName = j.next();
                int index = nameMap.get(attName);
                if (peIssuanceMode == null) {
                    peIssuanceMode = issuanceMode[index];
                    String primeEncodingName = getAttribute(primeEncodings
                            .item(i).getAttributes(), "name");
                    numValues[index] = Integer
                            .valueOf(getAttribute(primeEncodings.item(i)
                                    .getAttributes(), "numValues"));
                    if (tempMap.size() > numValues[index]) {
                        throw new RuntimeException("Number of attributes is "
                                + "declared to be at most " + numValues[index]
                                + " but it is actually " + tempMap.size());
                    }
                    nameMap.put(primeEncodingName, index);
                    name[index] = primeEncodingName;
                    dataType[index] = DataType.ENUM;
                    finalMap.put(primeEncodingName, tempMap);
                } else {
                    if (peIssuanceMode != issuanceMode[index]) {
                        throw (new RuntimeException("Issuance mode of prime "
                                + "encoded attributes must match."));
                    }
                    // optional: removal of values...
                    name[index] = "";
                    issuanceMode[index] = null;
                }
                nameMap.remove(attName);
            }
        }

        // Parsing AttributeOrder
        length = attribOrder.getLength();
        for (int i = 0; i < length; i++) {
            Node att = attribOrder.item(i);
            String name_order = getAttribute(att.getAttributes(), "name");
            int j = nameMap.get(name_order);
            publicKeyIndex[j] = Integer.parseInt(att.getFirstChild()
                    .getNodeValue());
        }

        // Creating attributes
        Vector<AttributeStructure> attStructures = new Vector<AttributeStructure>();
        for (int i = 0; i < name.length; i++) {
            if (name[i].equals("")) {
                continue;
            }
            AttributeStructure attStructure = new AttributeStructure(name[i],
                    publicKeyIndex[i], issuanceMode[i], dataType[i]);
            // setting map of prime encoded values
            attStructure.setPrimeEncodedFactors(finalMap.get(name[i]),
                    numValues[i]);
            attStructures.add(attStructure);
        }
        return attStructures;
    }

    /**
     * @param document
     *            Root of the document.
     * @return Issuer key pair.
     */
    private final Object parseIssuerSecretKey(final Document document) {
        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI issuerPublicKeyLocation = getURIValue(references, "IssuerPublicKey");

        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);

        BigInteger n = new BigInteger(getValue(elements, "n"));
        BigInteger p = new BigInteger(getValue(elements, "p"));
        BigInteger pPrime = new BigInteger(getValue(elements, "pPrime"));
        BigInteger q = new BigInteger(getValue(elements, "q"));
        BigInteger qPrime = new BigInteger(getValue(elements, "qPrime"));

        return new IssuerKeyPair(new IssuerPrivateKey(issuerPublicKeyLocation,
                n, p, pPrime, q, qPrime));
    }

    /**
     * @param document
     *            Root of the document.
     * @return Issuer public key.
     */
    private final Object parseIssuerPublicKey(final Document document) {
        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI groupParametersName = getURIValue(references, "GroupParameters");

        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);

        BigInteger capS = new BigInteger(getValue(elements, "S"));
        BigInteger capZ = new BigInteger(getValue(elements, "Z"));
        BigInteger n = new BigInteger(getValue(elements, "n"));
        BigInteger[] capR = parseBases(elements);

        Element features = (Element) document.getElementsByTagName("Features")
                .item(0);
        Element epoch = (Element) features.getElementsByTagName("Epoch")
                .item(0);
        int epochLength = Integer.parseInt(epoch.getAttribute("length"));

        return new IssuerPublicKey(groupParametersName, capS, capZ, capR, n,
                epochLength);
    }

    /**
     * @param elements
     *            Root of the called "elements".
     * @return Bases listed within the public key.
     */
    private final BigInteger[] parseBases(final Element elements) {
        Node bases = elements.getElementsByTagName("Bases").item(0);

        int numBases = Integer.parseInt(bases.getAttributes()
                .getNamedItem("num").getNodeValue());
        BigInteger[] capR = new BigInteger[numBases];

        for (int i = 0; i < numBases; i++) {
            capR[i] = new BigInteger(getValue(elements, "Base_" + i));
        }
        return capR;
    }

    /**
     * @param document
     *            Root of the document.
     * @return Translator.
     */
    private final Object parseMasterSecret(final Document document) {

        BigInteger value = new BigInteger(getValue(
                document.getDocumentElement(), "Value"));

        URI groupParamsLocation = getURIValue(document.getDocumentElement(),
                "GroupParameters");
        GroupParameters gp = (GroupParameters) StructureStore.getInstance()
                .get(groupParamsLocation);

        // Parse pseudonyms
        Element elements = (Element) document
                .getElementsByTagName("Pseudonyms").item(0);
        NodeList element = elements.getElementsByTagName("Pseudonym");
        HashMap<String, Nym> nymList = new HashMap<String, Nym>();
        for (int i = 0; i < element.getLength(); i++) {
            NamedNodeMap atts = element.item(i).getAttributes();
            String key = getAttribute(atts, "name");

            Nym nym = new Nym(gp, new BigInteger(getValue(element.item(i))),
                    key);
            nymList.put(key, nym);
        }

        elements = (Element) document.getElementsByTagName("DomainPseudonyms")
                .item(0);
        element = elements.getElementsByTagName("DomainPseudonym");
        HashMap<String, DomNym> domNymList = new HashMap<String, DomNym>();
        for (int i = 0; i < element.getLength(); i++) {
            NamedNodeMap atts = element.item(i).getAttributes();
            String key = getAttribute(atts, "name");

            DomNym domNym = new DomNym(gp, new BigInteger(
                    getValue(element.item(i))), new BigInteger(getAttribute(
                    atts, "g_Dom")));
            domNymList.put(key, domNym);
        }

        return new MasterSecret(value, groupParamsLocation, nymList, domNymList);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Group parameters.
     */
    private final Object parseGroupParameters(final Document document) {
        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI systemParametersName = getURIValue(references, "SystemParameters");

        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);

        BigInteger capGamma = new BigInteger(getValue(elements, "Gamma"));
        BigInteger g = new BigInteger(getValue(elements, "g"));
        BigInteger h = new BigInteger(getValue(elements, "h"));
        BigInteger rho = new BigInteger(getValue(elements, "rho"));

        return new GroupParameters(capGamma, rho, g, h, systemParametersName);
    }

    /**
     * @param document
     *            Root of the document.
     * @return System parameters.
     */
    private final SystemParameters parseSystemParameters(final Document document) {
        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);
        int l_e = Integer.parseInt(getValue(elements, "l_e"));
        int l_ePrime = Integer.parseInt(getValue(elements, "l_ePrime"));
        int l_Gamma = Integer.parseInt(getValue(elements, "l_Gamma"));
        int l_H = Integer.parseInt(getValue(elements, "l_H"));
        int l_k = Integer.parseInt(getValue(elements, "l_k"));
        int l_m = Integer.parseInt(getValue(elements, "l_m"));
        int l_n = Integer.parseInt(getValue(elements, "l_n"));
        int l_Phi = Integer.parseInt(getValue(elements, "l_Phi"));
        int l_pt = Integer.parseInt(getValue(elements, "l_pt"));
        int l_r = Integer.parseInt(getValue(elements, "l_r"));
        int l_res = Integer.parseInt(getValue(elements, "l_res"));
        int l_rho = Integer.parseInt(getValue(elements, "l_rho"));
        int l_v = Integer.parseInt(getValue(elements, "l_v"));
        // int t = Integer.parseInt(getValue(elements, "t"));
        int l_enc = Integer.parseInt(getValue(elements, "l_enc"));

        return new SystemParameters(l_e, l_ePrime, l_Gamma, l_H, l_k, l_m, l_n,
                l_Phi, l_pt, l_r, l_res, l_rho, l_v, l_enc);
    }

    /**
     * @param document
     *            Root of the document.
     * @return System parameters.
     */
    private final VEPrivateKey parseVerEncSecretKey(final Document document) {
        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI verEncPublicKey = getURIValue(references,
                "VerifiableEncryptionPublicKey");

        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);
        // BigInteger g = new BigInteger(getValue(elements, "g"));
        // BigInteger n = new BigInteger(getValue(elements, "n"));
        BigInteger orderN = new BigInteger(getValue(elements, "orderN"));
        BigInteger x1 = new BigInteger(getValue(elements, "x1"));
        BigInteger x2 = new BigInteger(getValue(elements, "x2"));
        BigInteger x3 = new BigInteger(getValue(elements, "x3"));

        return new VEPrivateKey(verEncPublicKey, orderN, x1, x2, x3);
    }

    /**
     * @param document
     *            Root of the document.
     * @return System parameters.
     */
    private final VEPublicKey parseVerEncPublicKey(final Document document) {
        Element references = (Element) document.getElementsByTagName(
                "References").item(0);
        URI sysParamLocation = getURIValue(references, "SystemParameters");

        Element elements = (Element) document.getElementsByTagName("Elements")
                .item(0);
        BigInteger g = new BigInteger(getValue(elements, "g"));
        BigInteger n = new BigInteger(getValue(elements, "n"));
        BigInteger y1 = new BigInteger(getValue(elements, "y1"));
        BigInteger y2 = new BigInteger(getValue(elements, "y2"));
        BigInteger y3 = new BigInteger(getValue(elements, "y3"));

        return new VEPublicKey(sysParamLocation, g, n, y1, y2, y3);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Proof.
     */
    private final Proof parseProof(final Document document) {

        BigInteger challenge = new BigInteger(getValue((Element) document
                .getElementsByTagName("Challenge").item(0)));

        // parse common values
        NodeList commonVals = ((Element) document.getElementsByTagName(
                "CommonValues").item(0)).getElementsByTagName("CommonValue");
        TreeMap<String, BigInteger> commonValues = new TreeMap<String, BigInteger>();

        for (int i = 0; i < commonVals.getLength(); i++) {
            NamedNodeMap commonVal = commonVals.item(i).getAttributes();
            String key = getAttribute(commonVal, "key");
            BigInteger value = new BigInteger(getValue(commonVals.item(i)));

            commonValues.put(key, value);
        }
        // parse s-values
        Node proofRoot = document.getElementsByTagName("IdmxProof").item(0);

        NodeList vals = ((Element) ((Element) proofRoot).getElementsByTagName(
                "Values").item(0)).getElementsByTagName("Value");
        Map<String, SValue> values = new HashMap<String, SValue>();

        for (int i = 0; i < vals.getLength(); i++) {
            NamedNodeMap val = vals.item(i).getAttributes();
            String key = getAttribute(val, "key");
            String type = getAttribute(val, "type");

            if (type.equalsIgnoreCase("BigInteger")) {
                values.put(key, new SValue(new BigInteger(
                        getValue(vals.item(i)))));
            } else if (type.equalsIgnoreCase("SValueIP")) {
                Element sValueIP = (Element) ((Element) vals.item(i))
                        .getElementsByTagName("SValueIP").item(0);
                BigInteger alphaHat = new BigInteger(getValue(sValueIP,
                        "AlphaHat"));

                int length = InequalityProver.NUM_SQUARES + 1;
                BigInteger[] uHat = new BigInteger[length];
                for (int j = 0; j < length - 1; j++) {
                    uHat[j] = new BigInteger(getValue(sValueIP, "uHat_" + j));
                }

                BigInteger[] rHat = new BigInteger[length];
                for (int j = 0; j < length; j++) {
                    rHat[j] = new BigInteger(getValue(sValueIP, "rHat_" + j));
                }
                values.put(key, new SValue(new SValuesIP(uHat, rHat, alphaHat)));
            } else if (type.equalsIgnoreCase("SValueProveCL")) {
                Element sValueProveCL = (Element) ((Element) vals.item(i))
                        .getElementsByTagName("SValueProveCL").item(0);
                BigInteger eHat = new BigInteger(
                        getValue(sValueProveCL, "eHat"));
                BigInteger vHatPrime = new BigInteger(getValue(sValueProveCL,
                        "vHatPrime"));

                values.put(key, new SValue(new SValuesProveCL(eHat, vHatPrime)));
            } else if (type.equalsIgnoreCase("SValueCGAND")) {
                Element sValueCGAND = (Element) ((Element) vals.item(i))
                        .getElementsByTagName("SValueCGAND").item(0);
                BigInteger mHat_h = new BigInteger(getValue(sValueCGAND,
                        "mHat_h"));
                BigInteger rHat = new BigInteger(getValue(sValueCGAND, "rHat"));

                values.put(key, new SValue(new SValuesCGAND(mHat_h, rHat)));
            } else if (type.equalsIgnoreCase("SValueCGNOT")) {
                Element sValueCGNOT = (Element) ((Element) vals.item(i))
                        .getElementsByTagName("SValueCGNOT").item(0);
                BigInteger aHat = new BigInteger(getValue(sValueCGNOT, "aHat"));
                BigInteger bHat = new BigInteger(getValue(sValueCGNOT, "bHat"));
                BigInteger rHatPrime = new BigInteger(getValue(sValueCGNOT,
                        "rHatPrime"));

                values.put(key, new SValue(new SValuesCGNOT(aHat, bHat,
                        rHatPrime)));
            } else if (type.equalsIgnoreCase("SValueCGOR")) {
                Element sValueCGOR = (Element) ((Element) vals.item(i))
                        .getElementsByTagName("SValueCGOR").item(0);
                BigInteger mHat_i = new BigInteger(getValue(sValueCGOR,
                        "mHat_i"));
                BigInteger alphaHat = new BigInteger(getValue(sValueCGOR,
                        "alphaHat"));
                BigInteger betaHat = new BigInteger(getValue(sValueCGOR,
                        "betaHat"));
                BigInteger rHat_0 = new BigInteger(getValue(sValueCGOR,
                        "rHat_0"));
                BigInteger rHat_1 = new BigInteger(getValue(sValueCGOR,
                        "rHat_1"));
                BigInteger rHat_2 = new BigInteger(getValue(sValueCGOR,
                        "rHat_2"));

                // TODO (pbi) add s values for other commitments

                values.put(key, new SValue(new SValuesCGOR(mHat_i, alphaHat,
                        betaHat, rHat_0, rHat_1, rHat_2)));
            }
        }

        // parse verifiable encryptions
        vals = ((Element) document
                .getElementsByTagName("VerifiableEncryptions").item(0))
                .getElementsByTagName("VerifiableEncryption");
        TreeMap<String, VerifiableEncryption> verEncs = new TreeMap<String, VerifiableEncryption>();

        for (int i = 0; i < vals.getLength(); i++) {
            Node node = vals.item(i);
            NamedNodeMap val = node.getAttributes();
            String key = getAttribute(val, "key");

            VerifiableEncryption enc = parseVerifiableEncryption((Element) node);

            verEncs.put(key, enc);
        }
        return new Proof(challenge, values, commonValues, verEncs);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Nonce.
     */
    private final BigInteger parseNonce(final Document document) {
        return new BigInteger(getValue((Element) document.getElementsByTagName(
                "Value").item(0)));
    }

    /**
     * @param document
     *            Root of the document.
     * @return Nonce.
     */
    private final UpdateSpecification parseUpdateSpecification(
            final Document document) {

        // parse base location of updates
        String baseLocation = getValue(document.getElementsByTagName("BaseURI")
                .item(0));

        // parse attributes that will be updated
        NodeList nodeList = ((Element) document.getElementsByTagName(
                "Attributes").item(0)).getElementsByTagName("Attribute");
        HashSet<String> attributes = new HashSet<String>();

        for (int i = 0; i < nodeList.getLength(); i++) {
            NamedNodeMap node = nodeList.item(i).getAttributes();
            String name = getAttribute(node, "name");
            // TODO (pbi) parse Interval and other attributes of the update

            attributes.add(name);
        }
        return new UpdateSpecification(baseLocation, attributes);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Nonce.
     */
    private final IssuerUpdateInformation parseIssuerUpdateInformation(
            final Document document) {

        Element updates = (Element) document.getElementsByTagName("Location")
                .item(0);
        URI ipkId = getURIValue(updates, "IssuerPublicKey");
        URI updateLocation = getURIValue(updates, "Update");
        URI credStructLocation = getURIValue(updates, "CredentialStructure");

        NodeList nodeList = ((Element) document.getElementsByTagName("Values")
                .item(0)).getElementsByTagName("Value");
        Values values = new Values(((IssuerPublicKey) StructureStore
                .getInstance().get(ipkId)).getGroupParams().getSystemParams());

        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            NamedNodeMap nodeAtts = node.getAttributes();
            String name = getAttribute(nodeAtts, "name");
            BigInteger value = new BigInteger(getValue(node));

            values.add(name, value);
        }

        Element doc = document.getDocumentElement();

        BigInteger capQ = new BigInteger(getValue(doc, "Q"));
        BigInteger vPrimePrime = new BigInteger(getValue(doc, "vPrimePrime"));
        BigInteger nonce = new BigInteger(getValue(doc, "Nonce"));
        BigInteger context = new BigInteger(getValue(doc, "Context"));

        return new IssuerUpdateInformation(ipkId, credStructLocation, capQ,
                vPrimePrime, values, updateLocation, nonce, context);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Nonce.
     */
    private final Message parseMessage(final Document document) {

        HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
        issuanceProtocolValues = new HashMap<Message.IssuanceProtocolValues, BigInteger>();
        NodeList nodeList = ((Element) document.getElementsByTagName("Values")
                .item(0)).getElementsByTagName("Value");

        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            NamedNodeMap nodeAtts = node.getAttributes();
            IssuanceProtocolValues name = IssuanceProtocolValues
                    .valueOf(getAttribute(nodeAtts, "name"));
            BigInteger value = new BigInteger(getValue(node));

            issuanceProtocolValues.put(name, value);
        }

        // Parse proof
        Proof proof = null;
        if(document.getElementsByTagName("IdmxProof").item(0) != null) {
        	proof = (Proof) parseProof(document);
        }
        
        // Parse updateLocation
        Node updateLocationNode = document.getElementsByTagName(
                "UpdateLocation").item(0);
        URI updateLocation = null;
        if (updateLocationNode != null) {
            updateLocation = getURIValue((Element) updateLocationNode, "Update");
        }

        return new Message(issuanceProtocolValues, proof, updateLocation);
    }

    /**
     * @param root
     *            Root of the document.
     * @return Verifiable encryption (verifier's side).
     */
    private final VerifiableEncryption parseVerifiableEncryption(
            final Element root) {

        Element elements = (Element) root.getElementsByTagName("Locations")
                .item(0);

        URI vePublicKeyLocation = null;
        try {
            vePublicKeyLocation = new URI(getValue(elements,
                    "VEPublicKeyLocation"));
        } catch (URISyntaxException e1) {
            e1.printStackTrace();
        }

        elements = (Element) root.getElementsByTagName("Elements").item(0);

        BigInteger u = new BigInteger(getValue(elements, "u"));
        BigInteger e = new BigInteger(getValue(elements, "e"));
        BigInteger v = new BigInteger(getValue(elements, "v"));
        BigInteger capL = new BigInteger(getValue(elements, "Label"));

        return new VerifiableEncryption(vePublicKeyLocation, u, e, v, capL);
    }

    /**
     * @param document
     *            Root of the document.
     * @return Verifiable encryption opening (prover's side).
     */
    private final VerifiableEncryptionOpening parseVerifiableEncryptionOpening(
            final Document document) {

        Element elements = (Element) document.getElementsByTagName("Locations")
                .item(0);

        URI vePublicKeyLocation = null;
        try {
            vePublicKeyLocation = new URI(getValue(elements,
                    "VEPublicKeyLocation"));
        } catch (URISyntaxException e1) {
            e1.printStackTrace();
        }

        elements = (Element) document.getElementsByTagName("Elements").item(0);

        BigInteger message = new BigInteger(getValue(elements, "Message"));
        BigInteger r = new BigInteger(getValue(elements, "r"));
        BigInteger capL = new BigInteger(getValue(elements, "Label"));

        return new VerifiableEncryptionOpening(message, r, vePublicKeyLocation,
                capL);
    }

}
