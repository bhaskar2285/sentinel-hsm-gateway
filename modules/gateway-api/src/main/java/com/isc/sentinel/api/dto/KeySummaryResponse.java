package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Builder
public class KeySummaryResponse {
    private String keyId;
    private String label;
    private String keyType;
    private String algo;
    private Integer keyLengthBits;
    private String status;
    private String kcv;
    private Long   bankRecId;
    private Long   branchRecId;
    private OffsetDateTime createdAt;

    /** Hex-encoded encrypted_blob bytes for vault dense display. May be null if key has no stored material. */
    private String encryptedBlobHex;
    /** Length of encrypted_blob in bytes. */
    private Integer encryptedBlobLen;
    /** Vendor that produced the key (THALES, UTIMACO, ...). */
    private String vendorOrigin;
    /** Expiry timestamp, null = no expiry. */
    private OffsetDateTime expiresAt;
}
