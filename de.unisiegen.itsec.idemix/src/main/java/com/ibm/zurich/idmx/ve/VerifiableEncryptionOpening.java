/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.ve;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.Utils;

/**
 * An Encryption object which also contains the randomness used to create the
 * encryption. The randomness is required by the prover.
 * Encryption/ProverEncryption is similar to Commitment/CommitmentOpening, the
 * prover holds ProveEncryption, while the verifier only has the Encryption.
 */
public class VerifiableEncryptionOpening extends VerifiableEncryption {

    /** Randomness used to create the verifiable encryption. */
    private final BigInteger r;
    /** Message that is encrypted. */
    private final BigInteger message;

    /**
     * Constructor using a BigInteger as label.
     * 
     * @param theMessage
     *            Message.
     * @param theR
     *            Randomness of the encryption.
     * @param vePublicKeyLocation
     *            Verifiable encryption public key.
     * @param theCapL
     *            Label of the encryption.
     */
    public VerifiableEncryptionOpening(final BigInteger theMessage,
            final BigInteger theR, final URI vePublicKeyLocation,
            final Object theCapL) {
        super(theMessage, theR, vePublicKeyLocation, theCapL);
        message = theMessage;
        r = theR;
    }

    /**
     * @return Randomness used for the encryption.
     */
    public final BigInteger getR() {
        return r;
    }

    /**
     * @return Encryption object (i.e., to the public information corresponding
     *         to this private encryption opening information).
     */
    public final VerifiableEncryption getEncryption() {
        return new VerifiableEncryption(message, r,
                super.getVEPublicKeyLocation(), super.getCapL());
    }

    /**
     * @return Serialization method: message of the encryption.
     */
    public final BigInteger getMessage() {
        return message;
    }

    /**
     * @return Human-readable description of this object.
     */
    public final String toStringPretty() {
        String s = super.toStringPretty() + " r = " + Utils.logBigInt(this.r)
                + " (ProverEncryption)";
        return s;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        VerifiableEncryptionOpening other = (VerifiableEncryptionOpening) obj;
        if (r == null) {
            if (other.r != null) {
                return false;
            }
        } else if (!r.equals(other.r)) {
            return false;
        }
        if (message == null) {
            if (other.message != null) {
                return false;
            }
        } else if (!message.equals(other.message)) {
            return false;
        }
        return true;
    }

}
