/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Fixed-base comb method, section 14.6.3 in the green crypto book (Menezes et
 * al.).
 * 
 * Precomputes exponentiated bases and thus speeds-up exponentiations on random
 * exponents.
 * 
 */
public class FixedBaseComb implements ModPow {
    // TODO (frp): I did not check this class
    private static Logger log = Logger.getLogger(FixedBaseComb.class.getName());

    /** array of pre-allocated and pre-computed values; base^{some-power}. */
    final BigInteger capG[][];

    /** the fixed base we're going to work on. */
    final BigInteger base;

    /** digit width of exponent, in bit. */
    final int h;

    /** length of row in exponent array, in bit. */
    final int a;

    /** nbr of words in row of exp array; ceil( a/WORD_SIZE). */
    int nbrOfWordsInRow;

    final int maxNbrOfExpoBits;

    /**
     * a parameter s.t. 0<= v <= a. Influences run-time vs. storage: a larger v
     * requires fewer multiplies, but more space (since b ~ a/v.).
     */
    final int v;

    /**
     * b = ceil(a/v). influences the run-time; the nbr of multiplications is a +
     * b - 2.
     */
    final int b;

    /** modulus used for modular exponentiation */
    final BigInteger modulus;

    /**
     * we use the native word size (integer, 32 bit) for efficiency reasons,
     * although wasting some space.
     */
    final static int WORD_SIZE = Integer.SIZE;
    final static int NEG_WORD_SIZE = ~WORD_SIZE;

    static int log2_word_size = 0;
    static {
        log2_word_size = 0;
        for (int i = 0; (1 << i) < WORD_SIZE; i++) {
            log2_word_size = log2_word_size + 1;
        }
    }

    /** Instance variable, exponent array. */
    int expArr[][] = null;

    /**
     * Computes capG[0][i].
     * 
     * @param capGRow0
     *            row 0 G.
     * @param h
     *            digit-width in exponent
     * @param i
     *            column in row 0 of G; ranges from [1..2^h - 1].
     * @param modulus
     *            reduction modulus
     * @return product of g_j^{i_j} for all j in [0..h-1].
     */
    final static BigInteger prodOfG(final BigInteger capGRow0[], int h, int i,
            final BigInteger modulus) {
        BigInteger p = BigInteger.ONE;

        // j is bit index into value of i.
        int bitmask = 1; // test @ bit 0 initially
        for (int j = 0; j < h; j++) {

            // test bit i_j
            if ((i & bitmask) != 0) {
                // bit i_j == 1 -> g_j^{i_j} == g_j.
                p = p.multiply(capGRow0[j]).mod(modulus);
            } // else bit_ij == 0; g^0 == 1

            // shift bitmask one left.
            bitmask = (bitmask << 1);
        }
        return p;
    }

    /**
     * Constructor.
     * 
     * @param base
     *            fixed base for exponentiation.
     * @param t
     *            max. nbr. of bits in exponent.
     * @param h
     *            nbr. of rows in exponent array, which will have a =
     *            ceil((t+1)/h) columns.
     * @param v
     *            1 <= v <= a with a == ceil((t+1)/h)
     * @param modulus
     */
    public FixedBaseComb(final BigInteger base, int t, int h, int v,
            final BigInteger modulus) {

        this.maxNbrOfExpoBits = t;

        // this is to compute I_jk later on: we need an integer index, and thus
        // can't have more than 32 rows in EA.
        if (h >= Integer.SIZE) {
            throw new IllegalArgumentException("h >= Integer.SIZE");
        }

        // nbr of bits per row.
        this.a = (int) Math.ceil((double) (t + 1) / h);

        if (v < 1 || v > a) {
            throw new IllegalArgumentException("v out of range");
        }

        this.h = h;
        this.v = v;
        this.b = (int) Math.ceil((double) this.a / this.v);

        this.base = base;
        this.modulus = modulus;

        if (this.base.equals(BigInteger.ONE)
                || this.base.equals(BigInteger.ZERO)) {
            this.capG = null;
            return;
        }

        log.log(Level.INFO, "allocating " + v * (1 << h)
                + " big-ints for G[][]");

        this.capG = new BigInteger[v][(1 << h)];
        final BigInteger g[] = new BigInteger[h];

        for (int i = 0; i < h; i++) {
            // compute 2^ia.
            final BigInteger exp = BigInteger.ONE.shiftLeft(i * a);
            // System.err.println( "exp[" + i + "]: " + exp.toString());
            g[i] = base.modPow(exp, this.modulus);
            // System.err.println( "g[" + i + "]: " + g[i].toString());
        }

        for (int i = 1; i < (1 << h); i++) {
            this.capG[0][i] = prodOfG(g, h, i, modulus);

            for (int j = 1; j < v; j++) {
                final BigInteger exp = BigInteger.ONE.shiftLeft(j * b);

                this.capG[j][i] = (this.capG[0][i]).modPow(exp, this.modulus);
            }
        }

        /*
         * for ( int j = 0; j < v; j++) { for ( int i = 1; i < (1<<h); i++) {
         * System.err.println( "G[" + j + "][" + i + "]: " +
         * capG[j][i].toString( 16)); } }
         */
    }

    /**
     * A cloning constructor.
     * 
     * @param fbc
     */
    public FixedBaseComb(FixedBaseComb fbc) {
        super();
        this.maxNbrOfExpoBits = fbc.maxNbrOfExpoBits;
        this.h = fbc.h;
        this.b = fbc.b;
        this.v = fbc.v;
        this.a = fbc.a;
        this.base = fbc.base;
        this.modulus = fbc.modulus;
        this.capG = fbc.capG;

        this.expArr = null;
        this.nbrOfWordsInRow = 0;

    }

    /**
     * Given the bitpos in big-int, get row index in exp array.
     * 
     * @param bitPos
     * @return row index in exp array.
     */
    private final int getRowIndex(int bitPos) {
        int row = bitPos / this.a;
        assert (row >= 0 && row < this.h);
        return row;
    }

    /**
     * Given the bitpos in big-int, get col index in exp array.
     * 
     * @param bitPos
     * @return column index in exp array.
     */
    private final int getColIdx(int bitPos) {
        int col = bitPos % this.a;
        assert (col >= 0 && col < this.a);
        return col;
    }

    // private final int getWordIdx(int colIdx) {
    // // int widx = colIdx/WORD_SIZE;
    // int widx = (colIdx >> log2_word_size);
    // assert (widx >= 0 && widx < this.nbrOfWordsInRow);
    // return widx;
    // }
    //
    // private final int getBitPos(int colIdx) {
    // // return colIdx % WORD_SIZE;
    // return colIdx & NEG_WORD_SIZE;
    // }

    private void loadExpArr(final BigInteger exp) {

        int nbrOfBits = exp.bitLength();

        // we traverse bits from LSB @ pos 0 towards MSB.
        for (int i = 0; i < nbrOfBits; i++) {

            // each row has this.a bits; we have h rows. start with 0 @ the top.
            int rowIdx = this.getRowIndex(i);

            // make sure to keep bit ordering. LSB is at col [a-1], on the
            // right.
            int colIdx = this.getColIdx(i);

            int wordIdx = (colIdx >> log2_word_size); // this.getWordIdx(
                                                      // colIdx);
            int bitPos = (colIdx & NEG_WORD_SIZE); // this.getBitPos( colIdx);

            assert (wordIdx < expArr[rowIdx].length);

            if (exp.testBit(i)) {
                // System.err.println( "i: " + i + " bitPos: " + bitPos);
                this.expArr[rowIdx][wordIdx] |= (1 << bitPos);
            } // else leave it 0.

        }
        // we don't need to worry about padding, as array is zero-filled.
    }

    /*
     * private boolean testBit( int row, int col) {
     * 
     * int colIdx = getColIdx( col);
     * 
     * assert( colIdx < this.a);
     * 
     * int wordIdx = (colIdx >> log2_word_size); // getWordIdx( colIdx); int
     * bitPos = (colIdx & NEG_WORD_SIZE); // getBitPos( colIdx);
     * 
     * assert( row < this.h); assert( wordIdx < this.expArr[row].length);
     * 
     * if (( this.expArr[ row][wordIdx] & (1<<bitPos)) != 0) { return true; }
     * return false; }
     */

    private int getI_jk(int j, int k) {

        assert (0 <= k && k < this.b);
        assert (0 <= j && j < this.v);

        // b == ceil( a/v) -> b*v <= a
        final int col = j * this.b + k;

        // if col == this.a, the index is out of bound
        // we return 0.
        if (col >= this.a)
            return 0;

        assert (col < this.a);

        int capI = 0;

        final int colIdx = getColIdx(col);
        final int wordIdx = (colIdx >> log2_word_size); // getWordIdx( colIdx);
        final int bitPos = (colIdx & NEG_WORD_SIZE); // getBitPos( colIdx);

        for (int row = 0; row < this.h; row++) {
            // if ( testBit( row, col)) {
            if ((this.expArr[row][wordIdx] & (1 << bitPos)) != 0) {
                // LSB is at the top.
                capI |= 1 << row;
            } // else: no-op
        }
        return capI;
    }

    private BigInteger getElemOfG(int j, int k) {
        final int capI_jk = getI_jk(j, k);

        assert (0 <= j && j < this.v); // row

        // it can be that I_jk returns 0, but G[j][0] is null.
        // we return 1 (neutral elem for multiply).
        if (capI_jk == 0) {
            return BigInteger.ONE;
        }

        // G was only initialized at col 1 and greater...
        assert ((1 <= capI_jk) && (capI_jk < (1 << this.h))); // column

        return this.capG[j][capI_jk];
    }

    /**
     * Sets all the values in exponent array to 0.
     */
    private void resetExpArr() {
        for (int i = 0; i < this.expArr.length; i++) {
            for (int j = 0; j < this.expArr[i].length; j++) {
                this.expArr[i][j] = 0;
            }
        }
    }

    /**
     * To compute base^exp mod( modulus).
     * 
     * @param exp
     * @param modulus
     * @return base^exp mod( modulus).
     */
    public BigInteger modPow(final BigInteger exp, final BigInteger modulus) {

        if (!this.modulus.equals(modulus)) {
            throw new IllegalArgumentException("modulus mismatch");
        }

        if (this.base.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        } else if (this.base.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }

        BigInteger exponent;
        boolean negFlag = false;
        if (exp.compareTo(BigInteger.ZERO) < 0) {
            negFlag = true;
            exponent = exp.negate();
        } else if (exp.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ONE;
        } else {
            exponent = exp;
        }

        if ((exponent.bitLength() + 1) > this.a * this.h) {
            log.log(Level.SEVERE,
                    "exponent bit length exceeded: " + exponent.bitLength()
                            + " > " + this.maxNbrOfExpoBits);
            throw new IllegalArgumentException(
                    "max bit length of exponent exceeded");
        }

        // compute row-width of EA. We take ints to be run-time efficient.
        // this.a: bit-width of exponent bit-strings.
        this.nbrOfWordsInRow = this.a / WORD_SIZE;
        if ((this.h % WORD_SIZE) != 0) { // need padding
            this.nbrOfWordsInRow += 1;
        }

        // allocate EA: h x a; h rows, a columns.
        if (this.expArr == null) {
            this.expArr = new int[h][this.nbrOfWordsInRow];
        } else { // we may reuse a previously allocated exponent array.
            if (h == this.expArr.length
                    && this.nbrOfWordsInRow == this.expArr[0].length) {
                resetExpArr();
            } else {
                this.expArr = new int[h][this.nbrOfWordsInRow];
            }
        }
        loadExpArr(exponent);

        BigInteger capA = BigInteger.ONE;

        for (int k = this.b - 1; k >= 0; k--) {
            // A = A * A
            capA = capA.multiply(capA).mod(this.modulus);

            for (int j = this.v - 1; j >= 0; j--) {
                final BigInteger elemOfG = getElemOfG(j, k);

                // A = G[j][I(j,k)] * A
                if (!elemOfG.equals(BigInteger.ONE))
                    capA = capA.multiply(elemOfG).mod(this.modulus);
            }
        }

        if (negFlag) {
            // we computed base^{-exponent} and need to invert this.
            capA = capA.modInverse(this.modulus);
        }
        return capA;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getBase()
     */
    public BigInteger getBase() {
        return this.base;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getMaxExpWidth()
     */
    public int getMaxExpWidth() {
        return this.maxNbrOfExpoBits;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getModulus()
     */
    public BigInteger getModulus() {
        return this.modulus;
    }
}
