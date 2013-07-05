/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zurich.idmx.issuance.update;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;

/**
 * Specification of the credential updates that will be done by the issuer. This
 * specification is referenced from the corresponding credential structure. All
 * attributes that will be updated must be known to the issuer.
 */
public class UpdateSpecification {

    /** Base location where updates will be published. */
    private URI baseLocation;

    /** Set of attribute names that will be updated. */
    private HashSet<String> attributes;

    /**
     * Constructor.
     * 
     * @param theAttributes
     *            Attribute names of the attributes that will be updated.
     */
    public UpdateSpecification(String theBaseLocation,
            HashSet<String> theAttributes) {
        try {
            baseLocation = new URI(theBaseLocation);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        attributes = theAttributes;
    }

    public final URI getBaseLocation() {
        return baseLocation;
    }

    /**
     * @param values
     *            Values that should be updated.
     * @return False if an attribute of the attributes named in
     *         <code>values</code> is not in the list of updateable attributes.
     */
    public final boolean verifyValues(Values values) {
        Iterator<String> it = values.iterator();
        while (it.hasNext()) {
            String attributeName = it.next();
            if (!attributes.contains(attributeName)) {
                return false;
            }
        }
        return true;
    }

    public final Vector<AttributeStructure> getCompliantAttributeSpecVector(
            Vector<AttributeStructure> attStructs) {
        Vector<AttributeStructure> compliantAttStructs = new Vector<AttributeStructure>();
        for (AttributeStructure attStruct : attStructs) {
            if (attributes.contains(attStruct.getName())) {
                compliantAttStructs.add(attStruct);
            }
        }
        return compliantAttStructs;
    }
}
