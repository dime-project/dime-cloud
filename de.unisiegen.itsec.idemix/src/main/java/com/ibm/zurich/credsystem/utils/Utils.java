/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zurich.credsystem.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.credsystem.Translator.HighLevelDataType;

/**
 *
 */
public class Utils extends com.ibm.zurich.idmx.utils.Utils{

    /** Logger. */
    private static Logger log = Logger.getLogger(Utils.class.getName());

    /** Digest used. */
    public static final String DIGEST_METHOD = "SHA-256";
    /** Number of bits per byte. */
    public static final int BYTE_BIT_LENGTH = 8;
    /** Bit length of a SHA-256 hash. */
    private static final int SHA_BIT_LENGTH = 256;

    Utils(){
        super();
    }
    
    /**
     * Parses a date given as a string. The returned date is encoded in the time
     * zone and format as indicated by the data type provided.
     * 
     * @param dataType
     *            Data type that defines the format of the date.
     * @param date
     *            Date as a string.
     * @return Date encoded in the indicated format and time zone.
     * @throws ParseException
     */
    public static Date parseDate(HighLevelDataType dataType, String date)
            throws ParseException {
        String dataTypeString = dataType.toString();
        String[] dataTypeStrings = dataTypeString.split("_", 4);
        if (dataTypeStrings.length < 4) {
            throw new RuntimeException("Wrong data type used for date "
                    + "encoding.");
        }
        DateFormat currentDateFormat = getDateFormat(dataTypeStrings[0]);
        currentDateFormat.setTimeZone(getTimeZone(dataTypeStrings));
        return currentDateFormat.parse(date);
    }

    /**
     * Determines the granularity of a date handling. Currently only day
     * granularity is implemented. It uses the date format YYYY/MM/DD.
     * 
     * @param dateFormatName
     *            Name of a valid date format.
     * @return Corresponding simple date format retrieved from the constants
     *         class.
     */
    private static DateFormat getDateFormat(String dateFormatName) {
        if (dateFormatName.equalsIgnoreCase("dateFormatDay")) {
            return Constants.DATE_FORMAT_DAY;
        }
        throw new RuntimeException("Date granularity not found: "
                + dateFormatName);
    }

    /**
     * Determines the time zone of a based on the data type of an attribute.
     * 
     * @param dataTypeStrings
     *            Strings retrieved from the splitting the data type at
     *            characters "_".
     * @return Time zone corresponding to the strings (i.e., GMT-11 to GMT+12).
     */
    private static TimeZone getTimeZone(String[] dataTypeStrings) {
        String sign = null;
        if (dataTypeStrings[2].equalsIgnoreCase("plus")) {
            sign = "+";
        } else if (dataTypeStrings[2].equalsIgnoreCase("minus")) {
            sign = "-";
        }
        String timeZoneID = dataTypeStrings[1] + sign + dataTypeStrings[3];
        return TimeZone.getTimeZone(timeZoneID);
    }

    /**
     * Encodes a date into a BigInteger that can be encoded in a credential. To
     * do so it counts the days between 1 January 1800 and the given date.
     * 
     * @param date
     *            Date to be encoded.
     * @param dataType
     *            Type of the date defining the time zone where it is used in.
     * @return BigInteger encoding the date: <tt>date - 1.1.1800</tt>.
     */
    public static BigInteger encode(final String date,
            final HighLevelDataType dataType) {
        /** Calendar initialised to the reference date 1800/01/01. */
        String dataTypeString = dataType.toString();
        String[] dataTypeStrings = dataTypeString.split("_", 4);
        Date referenceDate = null;
        Date currentDate = null;
        try {
            referenceDate = parseDate(dataType, Constants.DATE_ORIGIN);
            currentDate = parseDate(dataType, date);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        GregorianCalendar referenceCalendar = (GregorianCalendar) Calendar
                .getInstance(getTimeZone(dataTypeStrings));
        GregorianCalendar currentCalendar = (GregorianCalendar) referenceCalendar
                .clone();

        referenceCalendar.setTime(referenceDate);
        currentCalendar.setTime(currentDate);

        BigInteger difference = BigInteger.ZERO;

        while (currentCalendar.get(Calendar.YEAR) > referenceCalendar
                .get(Calendar.YEAR)) {
            referenceCalendar.add(Calendar.YEAR, 1);
            referenceCalendar.add(Calendar.DATE, -1);

            // add the number of days of the year
            difference = difference.add(BigInteger.valueOf(referenceCalendar
                    .get(Calendar.DAY_OF_YEAR)));

            referenceCalendar.add(Calendar.DATE, 1);
        }
        difference = difference.add(BigInteger.valueOf(currentCalendar
                .get(Calendar.DAY_OF_YEAR)
                - referenceCalendar.get(Calendar.DAY_OF_YEAR)));

        return difference;
    }

    /**
     * Encodes a string such that it can be used as attribute value within a
     * credential.
     * 
     * @param l_H
     *            Length of a hash (as defined in the system parameters).
     * @param string
     *            String to be encoded.
     * @return BigInteger encoding the given string.
     */
    public static BigInteger encode(final int l_H, final String string) {
        return hashOf(l_H, string);
    }

    private static BigInteger hashOf(final int l_H, final String string) {
        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(DIGEST_METHOD);
        } catch (final NoSuchAlgorithmException e1) {
            log.log(Level.SEVERE, e1.getMessage(), e1);
            throw new RuntimeException(e1.getMessage());
        }

        // length in bytes
        int hashLen = l_H / BYTE_BIT_LENGTH;
        if (DIGEST_METHOD.equals("SHA-256")) {
            if (hashLen < SHA_BIT_LENGTH / BYTE_BIT_LENGTH) {
                log.log(Level.SEVERE, "SHA-256: hashLen < " + SHA_BIT_LENGTH
                        + "/" + BYTE_BIT_LENGTH + " (" + hashLen + ")");
                throw new RuntimeException("Digest error");
            }
        }

        byte[] byteArray = new byte[hashLen];
        try {
            byteArray = digest.digest(string.getBytes());
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error calculating hash of string: ", e);
            throw new RuntimeException("Digest error");
        }
        return new BigInteger(byteArray);
    }
}
