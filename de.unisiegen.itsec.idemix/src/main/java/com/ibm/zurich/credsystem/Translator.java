/**
 * Copyright IBM Corporation 2010-2011.
 */
package com.ibm.zurich.credsystem;

import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import com.ibm.zurich.credsystem.utils.Utils;

/**
 * Translates data into BigIntegers which can be handled by the Identity Mixer
 * library.
 */
public class Translator {

    public static enum HighLevelDataType {
        /** Date attributes with a granularity of days and the given time zone. */
        /** GMT+12 */
        DATEFORMATDAY_GMT_PLUS_12,
        /** GMT+11 */
        DATEFORMATDAY_GMT_PLUS_11,
        /** GMT+10 */
        DATEFORMATDAY_GMT_PLUS_10,
        /** GMT+9 */
        DATEFORMATDAY_GMT_PLUS_9,
        /** GMT+8 */
        DATEFORMATDAY_GMT_PLUS_8,
        /** GMT+7 */
        DATEFORMATDAY_GMT_PLUS_7,
        /** GMT+6 */
        DATEFORMATDAY_GMT_PLUS_6,
        /** GMT+5 */
        DATEFORMATDAY_GMT_PLUS_5,
        /** GMT+4 */
        DATEFORMATDAY_GMT_PLUS_4,
        /** GMT+3 */
        DATEFORMATDAY_GMT_PLUS_3,
        /** GMT+2 */
        DATEFORMATDAY_GMT_PLUS_2,
        /** GMT+1 */
        DATEFORMATDAY_GMT_PLUS_1,
        /** GMT */
        DATEFORMATDAY_GMT_PLUS_0, DATEFORMATDAY_GMT_MINUS_0,
        /** GMT-1 */
        DATEFORMATDAY_GMT_MINUS_1,
        /** GMT-2 */
        DATEFORMATDAY_GMT_MINUS_2,
        /** GMT-3 */
        DATEFORMATDAY_GMT_MINUS_3,
        /** GMT-4 */
        DATEFORMATDAY_GMT_MINUS_4,
        /** GMT-5 */
        DATEFORMATDAY_GMT_MINUS_5,
        /** GMT-6 */
        DATEFORMATDAY_GMT_MINUS_6,
        /** GMT-7 */
        DATEFORMATDAY_GMT_MINUS_7,
        /** GMT-8 */
        DATEFORMATDAY_GMT_MINUS_8,
        /** GMT-9 */
        DATEFORMATDAY_GMT_MINUS_9,
        /** GMT-10 */
        DATEFORMATDAY_GMT_MINUS_10,
        /** GMT-11 */
        DATEFORMATDAY_GMT_MINUS_11,
        /** String. */
        STRING
    }

    /** Map using the encoded value as key to original value and data type. */
    private HashMap<BigInteger, Object[]> translationMap;
    
    public static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd");

    /**
     * Constructor. Use this constructor if no translation object exists for a
     * particular credential store.
     */
    public Translator() {
        this(new HashMap<BigInteger, Object[]>());
    }

    public Translator(HashMap<BigInteger, Object[]> theTranslationMap) {
        translationMap = theTranslationMap;
    }

    public HashMap<BigInteger, Object[]> getMap() {
        return translationMap;
    }

    /**
     * @param value
     *            Value that is encoded.
     * @param dataType
     *            Data type of the value.
     * @param encodedValue
     *            Encoding of the value.
     */
    private void addToTranslationMap(String value, HighLevelDataType dataType,
            BigInteger encodedValue) {
        Object[] translatedObject = new Object[2];
        translatedObject[0] = value;
        translatedObject[1] = dataType;
        if (!translationMap.entrySet().contains(translatedObject)) {
            translationMap.put(encodedValue, translatedObject);
        }
    }

    /**
     * @param date
     *            Date to be encoded.
     * @param dataType
     *            Method of encoding.
     * @return BigInteger encoding the given date w.r.t. the given encoding.
     */
    public BigInteger encode(String date, HighLevelDataType dataType) {
        BigInteger encodedValue = Utils.encode(date, dataType);
        addToTranslationMap(date, dataType, encodedValue);
        return encodedValue;
    }

    // public static BigInteger getEncoding(String date, HighLevelDataType
    // dataType) {
    // return Utils.encode(date, dataType);
    // }

    /**
     * @param l_H
     *            Length of the hash function output.
     * @param value
     *            String to be encoded.
     * @return Encoding of the string by creating a hash.
     */
    public BigInteger encode(int l_H, String value) {
        BigInteger encodedValue = Utils.encode(l_H, value);
        addToTranslationMap(value, HighLevelDataType.STRING, encodedValue);
        return encodedValue;
    }

    public Object decode(BigInteger encodedValue) {
        String result;
        Object[] highLevelData = translationMap.get(encodedValue);
        HighLevelDataType dataType = HighLevelDataType.valueOf(highLevelData[1]
                .toString());
        switch (dataType) {
        case STRING:
            result = (String) highLevelData[0];
            break;
        default:
            Date date = null;
            try {
                date = Utils.parseDate(dataType, (String) highLevelData[0]);
            } catch (ParseException e) {
                e.printStackTrace();
            }
            result = (DATE_FORMAT).format(date);
            break;
        }

        return result;
    }
}
