/**
 * Copyright IBM Corporation 2011.
 */
package com.ibm.zurich.idmx.api;

import java.math.BigInteger;

import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;

/**
 * Interface of the proover. This allows for a simple re-implementation of the
 * prover. This is essential if you want to change the location of credentials.
 */
public interface ProverInterface {

    /**
     * Builds an Identity mixer show-proof data structure, which can be passed
     * to the verifier for verification.
     * 
     * @param nonce
     *            The nonce used to guarantee the freshness of the proof.
     * @param proofSpecification
     *            Specification of the proof to be carried out.
     * @return Identity mixer show-proof data structure.
     */
    public abstract Proof buildProof(final BigInteger nonce,
            final ProofSpec proofSpecification);

}