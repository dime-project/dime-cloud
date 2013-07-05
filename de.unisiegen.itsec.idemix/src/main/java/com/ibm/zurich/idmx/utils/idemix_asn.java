/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zurich.idmx.utils;

import java.math.BigInteger;

/**
 * A standard externalizing representation of arrays of BigInteger, based on
 * ASN.1 BER encoding.
 * 
 * see also <a href="http://www.w3.org/Protocols/HTTP-NG/asn1.html>ASN1</a>.
 */
public final class idemix_asn {

    private static final int SEQ = 0x30;

    private static final int INT = 0x02;

    /**
     * To decode an ASN.1 BER encoded array of BigInteger.
     * 
     * @param asndata
     *            the ASN.1 BER encoded data.
     * @return array of BigInteger.
     */
    public static BigInteger[] decode(final byte[] asndata) {
        if (SEQ != (0xff & asndata[0])) {
            throw new IllegalArgumentException("Invalid BER compound");
        }
        int f = voff(asndata, 0); // start of current field
        int flen = vlen(asndata, 0);

        if ((f + flen != asndata.length) || (flen < 3)) {
            throw new IllegalArgumentException("Invalid BER compound");
        }

        if (INT != (0xff & asndata[f])) {
            throw new IllegalArgumentException("Invalid field count");
        }
        if (1 != asndata[f + 1]) {
            throw new IllegalArgumentException("Invalid field count");
        }
        final int n = asndata[f + 2];
        f += 3;
        flen -= 3;

        final BigInteger[] fields = new BigInteger[n];

        int i = 0;
        while (i < n) {
            if (INT != asndata[f]) {
                throw new IllegalArgumentException("Incorrect field");
            }

            final int s = voff(asndata, f);
            final int l = vlen(asndata, f);

            fields[i] = new BigInteger(subarray(asndata, s, l));

            flen -= (s + l - f);
            f = s + l;
            ++i;
        }

        if (0 != flen) {
            throw new IllegalArgumentException("Extra field(s)");
        }

        return fields;
    }

    /**
     * To ASN.1 BER encode an array of big-integers.
     * 
     * @param ints
     *            array of BigInteger to be encoded.
     * @return ASN.1 BER encoding of array.
     */
    public static byte[] encode(final BigInteger[] ints) {
        int len = 0;

        for (int i = 0; i < ints.length; ++i) {
            final int lf = ints[i].toByteArray().length;
            len += 1 + lenbytes(lf) + lf;
        }

        // field count <256
        len += 1 + lenbytes(ints.length) + 1; // INTEGER { fieldcount }
        len += 1 + lenbytes(len); // SEQUENCE { ... }

        // size query would return here ---------

        final byte[] asn = new byte[len];

        int off = len; // assume writing just before [off]

        for (int i = ints.length - 1; 0 <= i; --i) {
            final byte[] asnf = ints[i].toByteArray();
            System.arraycopy(asnf, 0, asn, off - asnf.length, asnf.length);
            off -= asnf.length;
            off = lenwrite(asn, off, asnf.length);
            asn[--off] = INT;
        }

        asn[--off] = (byte) ints.length;
        asn[--off] = 1;
        asn[--off] = INT;

        off = lenwrite(asn, off, asn.length - off);
        asn[--off] = SEQ;

        // assert this
        if (0 != off) {
            // FIXME (pbi) this case occurs if the array is "too large"
            throw new IllegalArgumentException("Internal error of BER encoding");
        }

        return asn;
    }

    /**
     * Bytes of DER field length.
     */
    private static int lenbytes(int len) {
        if (len <= 0x7f) {
            return 1;
        }

        int i = 1;
        while (0 < len) {
            len >>= 8;
            ++i;
        }

        return i;
    }

    // DER length bytes
    private static int lenwrite(final byte[] asn, int off, int len) {
        if (len <= 0x7f) {
            asn[--off] = (byte) len;
        } else {
            int i = 0x80;
            while (0 < len) {
                asn[--off] = (byte) len;
                len >>= 8;
                ++i;
            }
            asn[--off] = (byte) i;
        }

        return off;
    }

    // replace with off/len arrays
    private static byte[] subarray(final byte[] data, final int off,
            final int len) {
        final byte[] s = new byte[len];

        System.arraycopy(data, off, s, 0, len);

        return s;
    }

    // --------------------------------------------------------------------
    /**
     * Returns (non-negative) length of Value field.
     * 
     * @return length of value field.
     */
    public static int vlen(final byte[] data, final int off) {
        if (data.length < off + 2) {
            throw new IllegalArgumentException("Invalid BER field");
        }
        int v = 0xff & data[off + 1];
        int voff = 2;

        if (0x80 == v) {
            throw new IllegalArgumentException("Indefinite BER");
        }
        if (0x83 < v) {
            throw new IllegalArgumentException("BER len range");
        }

        if (0x80 < v) {
            int i = v - 0x80;
            v = 0;

            if (data.length < off + voff + i) {
                throw new IllegalArgumentException("Incomplete BER field");
            }

            while (0 < i--) {
                v = (v << 8) + (0xff & data[off + (voff++)]);
            }
        } else {
            if (data.length < off + voff + v) {
                throw new IllegalArgumentException("Incomplete BER field");
            }
        }

        return v;
    }

    /**
     * Returns offset of Value field. Call only after verifying length, as
     * checks are not replicated.
     * 
     * @return offset of value field.
     */
    public static int voff(final byte[] data, final int off) {
        final int lf = 0xff & data[off + 1];

        return off + 2 + ((lf < 0x80) ? 0 : lf - 0x80);
    }
}
