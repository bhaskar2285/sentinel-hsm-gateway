package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyCheckValueRequest {
    /** UUID of a stored key. Either this OR keyHex must be supplied. */
    private String keyId;

    /** Raw LMK-encrypted key/component blob (scheme prefix + hex), for the KCV of an
     *  unstored value such as a key-block component. Used when keyId is absent. */
    private String keyHex;

    /** Scheme of keyHex (U/T/S…). Required when keyHex is used. */
    private String scheme;

    /** Key type override (3H). If omitted, derived from the key record / defaults to 00A. */
    private String keyType;
}
