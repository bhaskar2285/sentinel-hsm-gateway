package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "hsm_key")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class HsmKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_uuid", nullable = false, unique = true)
    private UUID keyUuid;

    @Column(nullable = false)
    private String label;

    @Column(name = "key_type", nullable = false, length = 64)
    private String keyType;

    @Column(nullable = false, length = 32)
    private String algo;

    @Column(name = "key_length_bits", nullable = false)
    private Integer keyLengthBits;

    @Column(length = 255)
    private String usage;

    @Column(name = "owner_user_id", length = 128)
    private String ownerUserId;

    @Column(name = "owner_org", length = 128)
    private String ownerOrg;

    @Column(length = 16)
    private String kcv;

    @Column(name = "encrypted_blob", columnDefinition = "bytea")
    private byte[] encryptedBlob;

    @Column(name = "wrap_key_id")
    private Long wrapKeyId;

    @Column(name = "vendor_origin", length = 32)
    private String vendorOrigin;

    @Column(name = "lmk_idx")
    private Short lmkIdx;

    @Column(nullable = false, length = 16)
    private String status;

    @Column(nullable = false)
    private Integer version;

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String tags;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "activated_at")
    private OffsetDateTime activatedAt;

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @PrePersist
    void prePersist() {
        if (keyUuid == null) keyUuid = UUID.randomUUID();
        if (createdAt == null) createdAt = OffsetDateTime.now();
        if (status == null) status = "ACTIVE";
        if (version == null) version = 1;
    }
}
