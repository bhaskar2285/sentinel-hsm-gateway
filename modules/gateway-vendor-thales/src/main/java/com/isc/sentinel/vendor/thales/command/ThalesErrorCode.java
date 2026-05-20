package com.isc.sentinel.vendor.thales.command;

/**
 * Thales payShield error code lookup. Returned in byte position 2 of response body.
 * "00" = OK. Add entries as encountered.
 */
public final class ThalesErrorCode {

    private ThalesErrorCode() {}

    public static String describe(String code) {
        if (code == null) return "unknown";
        return switch (code) {
            case "00" -> "No error";
            case "01" -> "Verification failure";
            case "02" -> "Inappropriate key length for algorithm";
            case "04" -> "Invalid key type code";
            case "05" -> "Invalid key length flag";
            case "10" -> "Source key parity error";
            case "11" -> "Destination key parity error";
            case "12" -> "Contents of user storage not available";
            case "13" -> "Master key parity error";
            case "14" -> "PIN encrypted under LMK pair 02-03 is invalid";
            case "15" -> "Invalid input data";
            case "16" -> "Console or printer not ready / unavailable";
            case "17" -> "HSM not authorized / not in authorized state";
            case "18" -> "Document format definition not loaded";
            case "19" -> "Specified diebold table is invalid";
            case "20" -> "PIN block does not contain valid values";
            case "21" -> "Invalid index value";
            case "22" -> "Invalid account number";
            case "23" -> "Invalid PIN block format code";
            case "24" -> "PIN is fewer than 4 or more than 12 digits in length";
            case "25" -> "Decimalisation table error";
            case "26" -> "Invalid key scheme";
            case "27" -> "Incompatible key length";
            case "28" -> "Invalid key type";
            case "29" -> "Key function not permitted";
            case "30" -> "Invalid reference number";
            case "31" -> "Insufficient solicitation entries for batch";
            case "33" -> "LMK key change storage is corrupted";
            case "40" -> "Invalid firmware checksum";
            case "41" -> "Internal hardware/software error: bad RAM";
            case "42" -> "DES failure";
            case "43" -> "RSA Key Generation Failure";
            case "47" -> "Algorithm not licensed";
            case "49" -> "Private key error, report to supervisor";
            case "51" -> "Invalid message header";
            case "65" -> "Transaction Key Scheme set to None";
            case "67" -> "Command not licensed";
            case "68" -> "Command has been disabled";
            case "74" -> "Invalid digest info syntax (no hash mode only)";
            case "80" -> "Data length error";
            case "81" -> "Key block format error";
            case "82" -> "Key block check value error";
            case "83" -> "Invalid key block version ID";
            case "84" -> "Key block format not supported";
            case "85" -> "Key block field error";
            case "90" -> "Data parity error in request from host";
            case "91" -> "LRC error in request from host";
            case "92" -> "Count value not between limits";
            default -> "Vendor error " + code;
        };
    }
}
