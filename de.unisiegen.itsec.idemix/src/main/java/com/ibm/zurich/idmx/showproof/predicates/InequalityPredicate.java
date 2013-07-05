/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;

/**
 *
 */
public class InequalityPredicate extends Predicate {

    /** Operators for inequality proofs. */
    public static enum InequalityOperator {
        /** Strictly less than operator (<). */
        LT,
        /** Strictly greater than operator (>). */
        GT,
        /** Less than or equal operator (<=). */
        LEQ,
        /** Greater than or equal operator (>=). */
        GEQ;
    }

    /** Define whether the inequality is over another attribute or a constant. */
    public enum InequalityType {
        /** Inequality is against another attribute. */
        ATTRIBUTE,
        /** Inequality is against a constant. */
        CONSTANT
    };

    /** Unique string to refer to this range proof. */
    private final String name;
    /** Key that is used (usually an issuer public key). */
    private final IssuerPublicKey ipk;

    /** Identifier of the first attribute. */
    private final Identifier identifier1;
    /** Identifier of the attribute to compare against (if any). */
    private final Identifier identifier2;
    /** Constant to compare against (if any). */
    private final BigInteger constant;
    /** Operator of the inequality. */
    private final InequalityOperator operator;
    /** PredicateType of this predicate. */
    private InequalityType inequalityType;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the predicate.
     * @param publicKeyLocation
     *            Location of the issuer public key.
     * @param theIdentifier
     *            Identifier of the attribute.
     * @param theOperator
     *            Operator.
     * @param theConstant
     *            Constant to be compared against.
     */
    public InequalityPredicate(final String theName,
            final URI publicKeyLocation, final Identifier theIdentifier,
            final InequalityOperator theOperator, final BigInteger theConstant) {
        super(PredicateType.INEQUALITY);

        name = theName;
        ipk = (IssuerPublicKey) StructureStore.getInstance().get(
                publicKeyLocation);

        identifier1 = theIdentifier;
        identifier2 = null;
        constant = theConstant;
        operator = theOperator;
        inequalityType = InequalityType.CONSTANT;
    }

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the predicate.
     * @param publicKeyLocation
     *            Location of the issuer public key.
     * @param theIdentifier1
     *            Identifier of the first attribute.
     * @param theOperator
     *            Operator.
     * @param theIdentifier2
     *            Identifier of the second attribute.
     */
    public InequalityPredicate(final String theName,
            final URI publicKeyLocation, final Identifier theIdentifier1,
            final InequalityOperator theOperator,
            final Identifier theIdentifier2) {
        super(PredicateType.INEQUALITY);

        name = theName;
        ipk = (IssuerPublicKey) StructureStore.getInstance().get(
                publicKeyLocation);

        identifier1 = theIdentifier1;
        identifier2 = theIdentifier2;
        constant = null;
        operator = theOperator;
        inequalityType = InequalityType.ATTRIBUTE;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return PredicateType, which is either CONSTANT or ATTRIBUTE.
     */
    public final InequalityType getInequalityType() {
        return inequalityType;
    }

    /**
     * @return Operator of the inequality.
     */
    public final InequalityOperator getOperator() {
        return operator;
    }

    /**
     * @return Key whose bases are used for an inequality proof.
     */
    public final IssuerPublicKey getKey() {
        return ipk;
    }

    /**
     * @return The first argument of the predicate, which is an attribute.
     */
    public final Identifier getFirstArgumentIdentifier() {
        return identifier1;
    }

    /**
     * @return Random value associated to the first argument of the predicate.
     */
    public final BigInteger getFirstArgumentRandom() {
        return identifier1.getRandom();
    }

    /**
     * @return Value of the first argument of the predicate.
     */
    public final BigInteger getFirstArgumentValue() {
        return identifier1.getValue();
    }

    /**
     * @return Value of the second argument of the predicate (either of a
     *         constant or an attribute).
     */
    public final BigInteger getSecondArgument() {
        switch (getInequalityType()) {
        case CONSTANT:
            return constant;
        case ATTRIBUTE:
            return identifier2.getValue();
        default:
            throw new RuntimeException("Inequality type not implemented.");
        }
    }

    /**
     * @return The second argument of the predicate (either of a constant or an
     *         attribute). Makes only sense if the argument is an attribute
     *         (i.e., an identifier).
     */
    public final Identifier getSecondArgumentIdentifier() {
        return identifier2;
    }

    /**
     * @return Human-readable string of the predicate.
     */
    public final String toStringPretty() {
        String s = "";
        String secondArgument;
        if (inequalityType == InequalityType.CONSTANT) {
            secondArgument = Utils.logBigInt(constant);

        } else {
            secondArgument = identifier2.getName();
        }
        s += "InequalityPredicate(" + name + ", " + identifier1.getName()
                + ", " + operator.toString() + ", " + secondArgument + ")";
        return s;
    }
}
