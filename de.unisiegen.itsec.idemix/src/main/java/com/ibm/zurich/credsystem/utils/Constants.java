/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zurich.credsystem.utils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * Additional constants that are used on the credential system layer.
 */
public class Constants extends com.ibm.zurich.idmx.utils.Constants {

    /** Default time format for DAY granularity used within Identity Mixer. */
    public static final DateFormat DATE_FORMAT_DAY = new SimpleDateFormat(
            "yyyy/MM/dd");

    /** Origin of the date encoding. */
    public static final String DATE_ORIGIN = "1800/01/01";
}
