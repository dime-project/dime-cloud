/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.Representation;
import com.ibm.zurich.idmx.showproof.predicates.MessagePredicate;
import com.ibm.zurich.idmx.showproof.predicates.RepresentationPredicate;

/**
 *
 */
public final class Validation {

    /**
     * Utility class constructor.
     */
    private Validation() {
    }

    /**
     * Validates bases in a predicate (from the proof specification) and the
     * ones in the representation object (from within the library).
     * 
     * @param pred
     *            Representation predicate.
     * @param rep
     *            Representation object.
     */
    public static void validateRepresentation(
            final RepresentationPredicate pred, final Representation rep) {
        Vector<BigInteger> bases = pred.getBases();
        int i = 0;
        for (BigInteger base : bases) {
            if (!base.equals(rep.getBase(i++))) {
                throw new RuntimeException("Base number " + i + " given "
                        + "in the predicate does not match the base in "
                        + "the given representation. Values in the proof "
                        + "specification must match the values from the "
                        + "public key.");
            }
        }
    }

    /**
     * Validates that a message object equals the message given in a predicate.
     * 
     * @param pred
     *            Message predicate.
     * @param message
     *            Message object.
     */
    public static void validateMessage(final MessagePredicate pred,
            final MessageToSign message) {
        if (!message.getMessage().equalsIgnoreCase(pred.getMessage())) {
            throw new RuntimeException("Proof specification uses a different"
                    + "message than the one given to the prover.");
        }
    }

}
