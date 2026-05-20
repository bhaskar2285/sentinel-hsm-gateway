package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "hsm_pool")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class HsmPool {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 32)
    private String vendor;

    @Column(nullable = false, length = 128, unique = true)
    private String name;

    @Column(name = "lb_strategy", nullable = false, length = 32)
    private String lbStrategy;

    @Column(name = "kbpk_id")
    private Long kbpkId;

    @Column(nullable = false)
    private Boolean enabled;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @PrePersist
    void prePersist() {
        OffsetDateTime now = OffsetDateTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
        if (enabled == null) enabled = true;
        if (lbStrategy == null) lbStrategy = "ROUND_ROBIN";
    }
}
