/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zurich.credsystem.utils;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;

import javax.xml.parsers.*;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import com.ibm.zurich.credsystem.Translator;

/**
 * Class for object serialization to XML.
 */
public class XMLSerializer extends com.ibm.zurich.idmx.utils.XMLSerializer {

    /** Singleton design pattern. */
    private static XMLSerializer serializer;

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

    /**
     * @param object
     * @return
     * @throws ParserConfigurationException
     */
    @SuppressWarnings("unchecked")
    protected Document createDOM(Object object) {

        Document doc = super.createDOM(object);

        if (object instanceof Translator) {
            doc = serializeTranslator((Translator) object, doc);
        } else if (object instanceof HashMap<?, ?>) {
            doc = serializeCredentialNames((HashMap<URI, Object>) object, doc);
        } else if (object instanceof String) {
            doc = serializeAuthenticationCode((String) object, doc);
        }
        return doc;
    }

    private Document serializeAuthenticationCode(String authCode, Document doc) {
        Element root = doc.createElement("StoreInformation");
        setRootAttributes(root);
        doc.appendChild(root);

        Element attribute = null;
        Text text = null;

        attribute = doc.createElement("AuthenticationInformation");
        // the authentication value
        text = doc.createTextNode(authCode);
        attribute.appendChild(text);

        root.appendChild(attribute);

        return doc;
    }

    private Document serializeTranslator(Translator translator, Document doc) {
        Element root = doc.createElement("Translator");
        setRootAttributes(root);
        doc.appendChild(root);

        Element attributes = doc.createElement("Attributes");
        root.appendChild(attributes);

        Element attribute = null;
        Text text = null;

        Iterator<BigInteger> iterator = translator.getMap().keySet().iterator();
        while (iterator.hasNext()) {
            BigInteger key = (BigInteger) iterator.next();
            Object[] value = translator.getMap().get(key);

            attribute = doc.createElement("Attribute");
            // the encoded value
            attribute.setAttribute("key", key.toString());
            // the data type
            attribute.setAttribute("dataType", value[1].toString());
            // the original value
            text = doc.createTextNode(value[0].toString());
            attribute.appendChild(text);
            attributes.appendChild(attribute);
        }
        return doc;
    }

    private Document serializeCredentialNames(
            HashMap<URI, Object> credentialNamesMap, Document doc) {
        Element root = doc.createElement("CredentialIds");
        setRootAttributes(root);
        doc.appendChild(root);

        Text text = null;
        Iterator<URI> it = credentialNamesMap.keySet().iterator();
        while (it.hasNext()) {
            URI id = it.next();
            Element element = doc.createElement("CredentialId");
            text = doc.createTextNode(id.toString());
            element.appendChild(text);

            root.appendChild(element);
        }
        return doc;
    }
}
