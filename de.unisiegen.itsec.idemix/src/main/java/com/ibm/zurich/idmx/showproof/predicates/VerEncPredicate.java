/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Predicate to prove knowledge of a verifiable encryption.
 */
public class VerEncPredicate extends Predicate {

    /** String which refers to a ProverEncryption or Encryption object. */
    private final String name;
    /** Identifier for the verifiable encryption object. */
    private final Identifier identifier;

    /** Location of the public key the encryption was created. */
    private final URI vePublicKeyLocation;
    /** Convenience: Verifiable encryption public key. */
    private final VEPublicKey pk;
    /** If we do create it, we need to have the label too. */
    private final BigInteger label;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the predicate.
     * @param theIdentifier
     *            Identifier used for the verifiable encryption.
     * @param thePk
     *            Public key for which the encryption is made.
     * @param theLabel
     *            Label of the verifiable encryption.
     */
    public VerEncPredicate(final String theName,
            final Identifier theIdentifier, final URI thePk,
            final String theLabel) {
        super(Predicate.PredicateType.VERENC);
        name = theName;
        identifier = theIdentifier;
        vePublicKeyLocation = thePk;
        pk = (VEPublicKey) StructureStore.getInstance().get(thePk);
        label = Utils.hashString(theLabel, pk.getSystemParameters().getL_H());
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Name identifier of the verifiable encryption.
     */
    public final Identifier getIdentifier() {
        return identifier;
    }

    /**
     * @return Location of the verifiable encryption public key.
     */
    public final URI getVEPublicKeyLocation() {
        return vePublicKeyLocation;
    }

    /**
     * @return Public key for which the verifiable encryption is created.
     */
    public final VEPublicKey getPublicKey() {
        return pk;
    }

    /**
     * @return Label of the verifiable encryption if it has just been created.
     */
    public final BigInteger getLabel() {
        return label;
    }

    /**
     * @return Human-readable string of the predicate.
     */
    public final String toStringPretty() {
        String s = "VerEncPredicate(" + name + ", " + identifier.getName()
                + ")";
        return s;
    }

}
