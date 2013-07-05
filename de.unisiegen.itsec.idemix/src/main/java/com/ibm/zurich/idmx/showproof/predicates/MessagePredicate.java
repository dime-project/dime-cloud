/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

/**
 * Predicate to indicate that one or more messages must be signed as a part of
 * the proof. These messages are assumed to be held by both the prover and the
 * verifier and are simply added to the hash. The result is a Schnorr-like
 * signature.
 * 
 * The name field allows the spec to give a friendly name to the message, such
 * as "Contract" or "Terms of service".
 */
public class MessagePredicate extends Predicate {

    /** Name of the message. */
    private String name;
    /** Message. */
    private String message;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the message.
     * @param theMessage
     *            Message.
     */
    public MessagePredicate(final String theName, final String theMessage) {
        super(PredicateType.MESSAGE);
        name = theName;
        message = theMessage;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Message.
     */
    public final String getMessage() {
        return message;
    }

    /**
     * @return Human-readable description of this object.
     */
    public final String toStringPretty() {
        String s = "MessagePredicate(" + name + ")";
        return s;
    }

}
