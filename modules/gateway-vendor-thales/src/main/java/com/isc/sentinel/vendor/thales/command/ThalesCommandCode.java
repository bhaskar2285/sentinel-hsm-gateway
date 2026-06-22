package com.isc.sentinel.vendor.thales.command;

/**
 * Thales payShield 10K 2-letter host command codes.
 * Request/response pairs per Core Host Commands V1.0 + Host Programmer's Manual.
 *
 * Phase 1 + ported Phase 2 stubs. Add entries as commands are implemented.
 */
public enum ThalesCommandCode {

    /* Phase 1 */
    EI("EI", "EJ", "Generate Public/Private RSA Key Pair", 167),
    GI("GI", "GJ", "Import Key/Data under RSA Public Key",  182),
    A8("A8", "A9", "Export Key (under ZMK or TMK)",         59),
    B4("B4", "B5", "Form Key Block (TR-31 / X9.143 wrap)",   65),
    M2("M2", "M3", "Decrypt Data Block",                    384),

    /* Phase 2 — names for reference; impl added incrementally */
    A0("A0", "A1", "Generate a Key", 38),
    A2("A2", "A3", "Generate and Print a Component", 44),
    A4("A4", "A5", "Form a Key from Encrypted Components", 50),
    A6("A6", "A7", "Import a Key (under ZMK)", 52),
    BW("BW", "BX", "Translate Keys Old/New LMK + Migrate Key Type", 70),
    GK("GK", "GL", "Export Key under RSA Public Key", 189),

    JA("JA", "JB", "Generate a Random PIN", 207),
    DE("DE", "DF", "Generate an IBM PIN Offset", 209),
    DG("DG", "DH", "Generate an ABA PVV", 217),
    DA("DA", "DB", "Verify Terminal PIN (IBM 3624)", 256),
    DC("DC", "DD", "Verify Terminal PIN (VISA PVV)", 262),
    EA("EA", "EB", "Verify Interchange PIN (IBM 3624)", 259),
    EC("EC", "ED", "Verify Interchange PIN (VISA PVV)", 266),
    CA("CA", "CB", "Translate PIN TPK -> ZPK/BDK", 278),
    CC("CC", "CD", "Translate PIN ZPK -> ZPK", 282),
    BA("BA", "BB", "Encrypt Clear PIN under ZPK", 290),
    EE("EE", "EF", "Derive PIN from IBM Offset", 270),
    JC("JC", "JD", "Translate PIN TPK -> LMK", 212),
    JE("JE", "JF", "Translate PIN ZPK -> LMK", 215),
    JG("JG", "JH", "Translate PIN LMK -> ZPK", 220),

    CW("CW", "CX", "Generate CVV/CVC/CVV2", 243),
    CY("CY", "CZ", "Verify CVV/CVC/CVV2", 297),

    KQ("KQ", "KR", "Verify ARQC / Generate ARPC", 454),
    KW("KW", "KX", "Verify ARQC / Generate ARPC (EMV 4.x)", 458),

    M0("M0", "M1", "Encrypt Data Block", 377),
    M6("M6", "M7", "Generate MAC", 390),
    M8("M8", "M9", "Verify MAC", 396),

    GC("GC", "GD", "Export ZPK under ZMK (LMK -> ZMK)", 185),

    BU("BU", "BV", "Generate Key Check Value", 102),
    B2("B2", "B3", "Echo / Loopback", 75),
    NO("NO", "NP", "HSM Status (Echo)", 340),

    /* Phase 3 — 3DS / EMV advanced */
    LQ("LQ", "LR", "Generate HMAC on Block of Data (SPA2 AAV)", 179),
    LS("LS", "LT", "Verify HMAC on Block of Data (SPA2 AAV verify)", 181),
    PM("PM", "PN", "Verify Dynamic CVV/CVC (dCVV CVN17)", 252),
    RY("RY", "RZ", "Calculate/Verify Card Security Code (CSC/AEVV)", 257),

    /* New commands */
    HC("HC", "HD", "Generate TPK", 0),
    IA("IA", "IB", "Generate ZPK", 0),
    NG("NG", "NH", "Decrypt Encrypted PIN", 0),
    OA("OA", "OB", "Generate Random Data", 0),
    JS("JS", "JT", "Translate PIN ZPK -> ZPK (variant 2)", 0),
    VA("VA", "VB", "Verify MAC (full-format variant)", 0),
    NC("NC", "ND", "Network Connectivity Check", 337),

    /* Legacy / specialised — formatting, mailer print, LMK migration, DUKPT */
    PA("PA", "PB", "Load Formatting Data to HSM", 235),
    PC("PC", "PD", "Load Additional Formatting Data to HSM", 236),
    PE("PE", "PF", "Print PIN / Solicitation Data", 224),
    BG("BG", "BH", "Translate PIN from Old LMK to New LMK", 69),
    G0("G0", "G1", "Translate PIN DUKPT -> ZPK / DUKPT", 339),
    GO("GO", "GP", "Verify PIN (DUKPT BDK + PVK)", 344);

    private final String request;
    private final String response;
    private final String description;
    private final int specPage;

    ThalesCommandCode(String request, String response, String description, int specPage) {
        this.request = request;
        this.response = response;
        this.description = description;
        this.specPage = specPage;
    }

    public String request()     { return request; }
    public String response()    { return response; }
    public String description() { return description; }
    public int specPage()       { return specPage; }

    public static ThalesCommandCode fromRequest(String code) {
        if (code == null) return null;
        for (ThalesCommandCode c : values()) if (c.request.equals(code)) return c;
        return null;
    }

    public static ThalesCommandCode fromResponse(String code) {
        if (code == null) return null;
        for (ThalesCommandCode c : values()) if (c.response.equals(code)) return c;
        return null;
    }
}
