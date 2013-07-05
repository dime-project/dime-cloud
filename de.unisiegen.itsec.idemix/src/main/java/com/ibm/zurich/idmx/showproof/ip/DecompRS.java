/**
 * Copyright IBM Corporation 2008-2011.
 */

package com.ibm.zurich.idmx.showproof.ip;

import java.math.BigInteger;
import java.util.HashMap;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Rabin-Shallit decomposition of an integer into a sum of 4 squares.
 */
public final class DecompRS {

    /** Convenience: Constant 4. */
    private static final BigInteger FOUR = BigInteger.valueOf(4L);

    /** Convenience: Constant 8. */
    private static final BigInteger EIGHT = BigInteger.valueOf(8L);

    /**
     * HashMap containing the special decomposition cases of the
     * RS-decomposition.
     */
    private static final HashMap<BigInteger, int[]> specDec = new HashMap<BigInteger, int[]>();

    // initialization
    static {
        specDec.put(BigInteger.valueOf(2), (new int[] { 1, 1 }));
        specDec.put(BigInteger.valueOf(3), (new int[] { 1, 1, 1 }));
        specDec.put(BigInteger.valueOf(10), (new int[] { 3, 1 }));
        specDec.put(BigInteger.valueOf(34), (new int[] { 3, 3, 4 }));
        specDec.put(BigInteger.valueOf(58), (new int[] { 3, 7 }));
        specDec.put(BigInteger.valueOf(85), (new int[] { 6, 7 }));
        specDec.put(BigInteger.valueOf(130), (new int[] { 3, 11 }));
        specDec.put(BigInteger.valueOf(214), (new int[] { 3, 6, 13 }));
        specDec.put(BigInteger.valueOf(226), (new int[] { 8, 9, 9 }));
        specDec.put(BigInteger.valueOf(370), (new int[] { 8, 9, 15 }));
        specDec.put(BigInteger.valueOf(526), (new int[] { 6, 7, 21 }));
        specDec.put(BigInteger.valueOf(706), (new int[] { 15, 15, 16 }));
        specDec.put(BigInteger.valueOf(730), (new int[] { 1, 27, 0 }));
        specDec.put(BigInteger.valueOf(1414), (new int[] { 6, 17, 33 }));
        specDec.put(BigInteger.valueOf(1906), (new int[] { 13, 21, 36 }));
        specDec.put(BigInteger.valueOf(2986), (new int[] { 21, 32, 39 }));
        specDec.put(BigInteger.valueOf(9634), (new int[] { 56, 57, 57 }));
    }

    /**
     * Array with all primes smaller than 7920.
     */
    private static final long[] PRIME_TABLE = { 2, 3, 5, 7, 11, 13, 17, 19, 23,
            29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
            101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
            167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
            313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
            397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
            467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
            569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
            643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
            733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821,
            823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
            911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
            1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063,
            1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
            1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
            1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301,
            1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
            1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481,
            1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553,
            1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
            1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709,
            1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
            1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879,
            1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
            1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063,
            2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137,
            2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239,
            2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311,
            2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389,
            2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
            2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591,
            2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677,
            2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731,
            2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
            2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909,
            2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
            3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109,
            3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
            3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307,
            3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373,
            3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469,
            3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557,
            3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637,
            3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
            3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823,
            3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
            3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007,
            4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093,
            4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201,
            4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271,
            4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373,
            4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481,
            4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567,
            4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
            4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759,
            4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871,
            4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957,
            4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023,
            5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119,
            5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233,
            5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347,
            5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437,
            5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519,
            5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
            5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701,
            5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807,
            5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869,
            5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007,
            6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091,
            6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199,
            6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277,
            6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359,
            6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469,
            6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
            6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679,
            6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779,
            6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863,
            6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961,
            6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039,
            7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159,
            7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247,
            7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369,
            7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489,
            7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
            7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649,
            7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741,
            7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867,
            7873, 7877, 7879, 7883, 7901, 7907, 7919 };

    /**
     * Constructor.
     */
    private DecompRS() {
    }

    /**
     * Decomposition into two squares using Jacobi. The decomposition is taken
     * out in the following steps, where p is the number to be decomposed: 0. (p
     * == 4h+ 1) && (p is prime) 1. find a with (a^2h == -1 mod p) 2. (b = a^h),
     * use b as imagianry number as (b^2 = a^2h = -1 mod p) 3. reduce
     * (p+i)=(p,b) to (x+yi)=(x,y) ... ggT
     * 
     * In the case where p is not prime the function returns 0,0 which indicates
     * the failure. If (p == 4h+1) is not fulfilled an exception could be
     * thrown.
     * 
     * @param numToDecompose
     *            The number which is to be decomposed.
     * @return The roots of the two square which add up to numToDecompose.
     */
    private static BigInteger[] sumOfTwoSquares(
            final BigInteger numToDecompose, final BigInteger[] result) {
        BigInteger a, b, temp;
        int i = 0;
        long h;

        // check if the prerequisite is fulfilled
        if (numToDecompose.mod(FOUR).equals(BigInteger.ONE)) {
            h = numToDecompose.divide(FOUR).longValue();
            // special case h==0: wherefore p==1
            if (h == 0) {
                result[0] = BigInteger.ONE;
                return result;
            }
            // case p==5 mod 8: set starting prime to 2
            if (numToDecompose.mod(EIGHT).equals(BigInteger.valueOf(5L))) {
                // set a = 2;
                a = BigInteger.valueOf((long) PRIME_TABLE[i]);
            }
            // case p==1 mod 8: set starting prime to 3
            else {
                assert numToDecompose.mod(EIGHT).equals(BigInteger.ONE);
                a = BigInteger.valueOf((long) PRIME_TABLE[++i]);
                while (a.modPow(numToDecompose.divide(Utils.TWO),
                        numToDecompose).equals(BigInteger.ONE)) {
                    a = BigInteger.valueOf((long) PRIME_TABLE[++i]);
                }
            }
            a = a.modPow(numToDecompose.divide(FOUR), numToDecompose);
            b = numToDecompose;
            while (a.pow(2).compareTo(numToDecompose) == 1) {
                temp = b;
                b = a;
                a = temp.mod(a);
            }
            result[0] = b.mod(a);
            result[1] = a;
        } else {
            // this case should never arise as (p==1 mod 4) is a precondition
            throw new RuntimeException("DecompRS#sumOfTwoSquares():"
                    + " Precondition violation: p != 1 mod 4");
        }
        return result;
    }

    /**
     * Calculates the next value of the Newton iteration.
     * 
     * @param square
     *            value for which the root is wanted.
     * @param root
     *            best estimation for the root so far.
     * @return next estimation calculated as <tt>(root+ square/root)/2</tt>.
     */
    private static BigInteger newtonIteration(final BigInteger square,
            final BigInteger root) {
        return root.add(square.divide(root)).divide(BigInteger.valueOf(2L));
    }

    /**
     * Returns the squareroot of the input. The root is calculated using Newton
     * iteration where the estimation is carried out as long as the difference
     * of the magnitude of the next step of the Newton iteration is greater than
     * one or the root is not found.
     * 
     * @param square
     *            the number whose root is to be found.
     * @return an approximation of the root of <tt>square</tt>.
     */
    private static BigInteger squareRoot(final BigInteger square) {
        BigInteger root = BigInteger.ONE;
        BigInteger oldRoot = root;
        root = newtonIteration(square, root);

        while ((root.subtract(oldRoot).abs().compareTo(BigInteger.ONE) == 1)
                || (root.pow(2).compareTo(square) > 0)) {
            oldRoot = root;
            root = newtonIteration(square, root);
        }
        return root;
    }

    /**
     * Rabin-Shallit decomposition of integers. The decomposition is done by the
     * reduction of the possible cases which are the following: 1. The number to
     * be decomposed is 0 (p==0) 2. The number is of the form (2^2h * x) 2.1. it
     * is a square root 2.2. it has a special decomposition (see
     * specialCaseRS[][]) 2.3. it fulfills (p==1 mod 4) and is prime 2.4. it
     * fulfills (p==1 mod 4) or (p==2 mod 4) 2.5.
     * 
     * @param sp
     *            System parameters (needed for the prime probability).
     * @param numToDecompose
     *            The integer that needs to be expressed in at most four squares
     *            (for convenience called p). must be >= 0.
     * 
     * @return The roots of the numbers which - when squared - add up to the
     *         value of numToDecompose. If the decomposition can be done using
     *         fewer than four values the remaining values are set to 0.
     */
    public static BigInteger[] decomposeInteger(final SystemParameters sp,
            BigInteger numToDecompose) {
        BigInteger[] result = { BigInteger.ZERO, BigInteger.ZERO,
                BigInteger.ZERO, BigInteger.ZERO };
        BigInteger temp, approxSquareroot, z;
        int shift = 0;
        int l_pt = sp.getL_pt();

        // case p is negative
        if (numToDecompose.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException(
                    "Rabin-Shallit called with a negative number.");
        }
        // case p==0
        if (numToDecompose.equals(BigInteger.ZERO)) {
            // result is [0, 0, 0, 0]
            return result;
        } else if (numToDecompose.equals(BigInteger.ONE)) {
            // result is [1, 0, 0, 0]
            result[0] = BigInteger.ONE;
            return result;
        }

        // p is of the form (4^q(x))
        while (numToDecompose.mod(FOUR).equals(BigInteger.ZERO)) {
            numToDecompose = numToDecompose.divide(FOUR);
            shift++;
        }
        // if x has an exact square root, we're done
        approxSquareroot = squareRoot(numToDecompose);
        if (approxSquareroot.pow(2).equals(numToDecompose)) {
            result[0] = approxSquareroot;
            return shiftResult(result, shift);
        }

        // if x==8k+1, may be two squares if x is prime
        // if x==8k+5, may be two squares if x is prime
        if (numToDecompose.mod(FOUR).equals(BigInteger.ONE)
                && numToDecompose.isProbablePrime(l_pt)) {
            result = sumOfTwoSquares(numToDecompose, result);
            // if decomposition into two squares is successful, we're done
            if (!result[0].equals(BigInteger.ZERO)) {
                return shiftResult(result, shift);
            }
        }
        // if x==8k+7: four squares where x=8k+6+1
        if (numToDecompose.mod(EIGHT).equals(BigInteger.valueOf(7L))) {
            result[3] = BigInteger.ONE;
            numToDecompose = numToDecompose.subtract(BigInteger.ONE);
        }
        // if x has a special decomposition, we're done
        if (specDec.containsKey(numToDecompose)) {
            int[] decomp = (int[]) specDec.get(numToDecompose);
            for (int j = 0; j < decomp.length; j++) {
                result[j] = BigInteger.valueOf(decomp[j]);
            }
            return shiftResult(result, shift);
        }

        // if x==8k+1, 8k+2, 8k+5, 8k+6: three squares and x==z^2+(4k+1)
        if (numToDecompose.mod(FOUR).equals(BigInteger.ONE)
                || numToDecompose.mod(FOUR).equals(BigInteger.valueOf(2L))) {
            // subtract a the biggest square smaller than p
            z = approxSquareroot;
            while (z.compareTo(BigInteger.ZERO) == 1) {
                temp = numToDecompose.subtract(z.pow(2));

                if (temp.mod(FOUR).equals(BigInteger.ONE)
                        && temp.isProbablePrime(l_pt)) {
                    result = sumOfTwoSquares(temp, result);
                    if (!result[0].equals(BigInteger.ZERO)) {
                        result[2] = z;
                        return shiftResult(result, shift);
                    }
                }
                z = z.subtract(BigInteger.ONE);
            }
        }
        // if x==8k+3: three squares and x==z^2+(2*(4k+1))
        if (numToDecompose.mod(EIGHT).equals(BigInteger.valueOf(3L))) {
            z = approxSquareroot;
            while (z.compareTo(BigInteger.ZERO) == 1) {
                temp = numToDecompose.subtract(z.pow(2));
                if (!temp.mod(EIGHT).equals(BigInteger.valueOf(2L))) {
                    z = z.subtract(BigInteger.ONE);
                    continue;
                }
                // divide by 2 to get a number of the form (4k+1)
                temp = temp.shiftRight(1);
                if (temp.isProbablePrime(l_pt)) {
                    result = sumOfTwoSquares(temp, result);
                    if (!result[0].equals(BigInteger.ZERO)) {
                        result[1] = result[1].add(result[0]);
                        result[0] = result[1].subtract(result[0].shiftLeft(1))
                                .abs();
                        result[2] = z;
                        return shiftResult(result, shift);
                    }
                }
                z = z.subtract(BigInteger.ONE);
            }
        }
        return result;
    }

    /**
     * Returns <tt>result&lt;&lt;shift</tt>. The number is divided by four as
     * long as it is zero modulo four. This shift has to be reversed before
     * returning the result.
     * 
     * @param result
     *            the result of the decomposition.
     * @param shift
     *            the shift.
     * @return <tt>result&lt;&lt;shift</tt>.
     */
    private static BigInteger[] shiftResult(final BigInteger[] result,
            final int shift) {
        int i = 0;
        while ((i < 4) && !result[i].equals(BigInteger.ZERO)) {
            result[i] = result[i].multiply(BigInteger.valueOf(2L).pow(shift));
            i++;
        }
        return result;
    }

}
