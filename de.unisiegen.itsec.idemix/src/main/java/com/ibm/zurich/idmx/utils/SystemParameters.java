/**
 * 
 */
package com.ibm.zurich.idmx.utils;

/**
 * Idemix system parameters.
 * 
 */
public class SystemParameters {

    /** Length of the modulus. */
    private final int l_n;
    private final int l_Gamma;
    private final int l_rho;
    /** Length of messages in the CL signature. */
    private final int l_m;
    /** Number of reserved attributes. */
    private final int l_res;
    /** Length of CL-signature value <tt>e</tt>. */
    private final int l_e;
    /** Length of value <tt>e'</tt>. */
    private final int l_prime_e;
    /** Length of CL-signature value <tt>v</tt>. */
    private final int l_v;
    /** Length to attain statistical zero-konwledge. */
    private final int l_Phi;
    private final int l_k;
    /** Length of hash function used. */
    private final int l_H;
    private final int l_r;
    /** Prime probability. */
    private final int l_pt;

    /**
     * Security parameter for the CS encryption scheme (used for verifiable
     * encryption).
     */
    private final int l_enc;

    public SystemParameters(int _l_e, int _l_prime_e, int _l_Gamma, int _l_H,
            int _l_k, int _l_m, int _l_n, int _l_Phi, int _l_pt, int _l_r,
            int _l_res, int _l_rho, int _l_v, int _l_enc)
            throws IllegalArgumentException {
        l_e = _l_e;
        l_Gamma = _l_Gamma;
        l_H = _l_H;
        l_k = _l_k;
        l_m = _l_m;
        l_n = _l_n;
        l_Phi = _l_Phi;
        l_prime_e = _l_prime_e;
        l_pt = _l_pt;
        l_r = _l_r;
        l_res = _l_res;
        l_rho = _l_rho;
        l_v = _l_v;
        l_enc = _l_enc;

        checkConstraints();
    }

    /**
     * @return Modulus length.
     */
    public final int getL_n() {
        return l_n;
    }

    /**
     * @return Length of the order of the commitment group.
     */
    public final int getL_Gamma() {
        return l_Gamma;
    }

    /**
     * @return Length of the subgroup of the commitment group.
     */
    public final int getL_rho() {
        return l_rho;
    }

    /**
     * @return Length of the messages.
     */
    public final int getL_m() {
        return l_m;
    }

    /**
     * @return Number of the reserved attributes (e.g., master secret).
     */
    public final int getL_res() {
        return l_res;
    }

    /**
     * @return Length of <tt>e</tt>/
     */
    public final int getL_e() {
        return l_e;
    }

    /**
     * @return l_prime_e
     */
    public final int getL_ePrime() {
        return l_prime_e;
    }

    /**
     * @return l_v
     */
    public final int getL_v() {
        return l_v;
    }

    /**
     * @return Statistical zero knowledge security parameter.
     */
    public final int getL_Phi() {
        return l_Phi;
    }

    /**
     * @return l_k
     */
    public final int getL_k() {
        return l_k;
    }

    /**
     * @return Length of a hash.
     */
    public final int getL_H() {
        return l_H;
    }

    /**
     * @return the l_r
     */
    public final int getL_r() {
        return l_r;
    }

    /**
     * @return Prime probability when generating random values.
     */
    public final int getL_pt() {
        return l_pt;
    }

    /**
     * @return Security parameter for the CS encryption scheme (used for
     *         verifiable encryption).
     */
    public final int getL_enc() {
        return l_enc;
    }

    /**
     * Verifies that all security relevant constraints are respected.
     */
    private void checkConstraints() {
        if (l_e <= (l_Phi + l_H + Math.max(l_m + 4, l_prime_e + 2))) {
            throw new IllegalArgumentException("constraint 1");
        }
        if (l_v <= (l_n + l_Phi + l_H + Math.max(l_m + l_r + 3, l_Phi + 2))) {
            throw new IllegalArgumentException("constraint 2");
        }
        if (l_H < l_k) {
            throw new IllegalArgumentException("constraint 3");
        }
        if (l_H >= l_e) {
            throw new IllegalArgumentException("constraint 5");
        }
        if (l_prime_e >= l_e - l_Phi - l_H - 3) {
            throw new IllegalArgumentException("constraint 6");
        }
        if (l_rho > l_m) {
            throw new IllegalArgumentException("constraint 7");
        }
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof SystemParameters)) {
            return false;
        }
        if (this == o) {
            return true;
        }
        SystemParameters sp = (SystemParameters) o;
        return (l_n == sp.l_n && l_Gamma == sp.l_Gamma && l_rho == sp.l_rho
                && l_m == sp.l_m && l_res == sp.l_res && l_e == sp.l_e
                && l_prime_e == sp.l_prime_e && l_v == sp.l_v
                && l_Phi == sp.l_Phi && l_k == sp.l_k && l_H == sp.l_H
                && l_r == sp.l_r && l_pt == sp.l_pt);
    }

    @Override
    public final int hashCode() {
        int tmp = l_n;
        tmp += l_Gamma;
        tmp += l_rho;
        tmp += l_m;
        tmp += l_res;
        tmp += l_e;
        tmp += l_prime_e;
        tmp += l_v;
        tmp += l_Phi;
        tmp += l_k;
        tmp += l_H;
        tmp += l_r;
        tmp += l_pt;
        tmp += l_enc;
        return tmp;
    }

}
