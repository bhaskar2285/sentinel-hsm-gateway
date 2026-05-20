package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "hsm_node")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class HsmNode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "pool_id", nullable = false)
    private Long poolId;

    @Column(nullable = false, length = 32)
    private String vendor;

    @Column(nullable = false)
    private String host;

    @Column(nullable = false)
    private Integer port;

    @Column(nullable = false)
    private Integer weight;

    @Column(nullable = false, length = 16)
    private String direction;     // OUTBOUND | INBOUND

    @Column(nullable = false)
    private Boolean enabled;

    @Column(nullable = false, length = 16)
    private String health;        // UP|DOWN|UNKNOWN|DRAINING

    @Column(name = "last_seen")
    private OffsetDateTime lastSeen;

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
        if (weight == null) weight = 1;
        if (direction == null) direction = "OUTBOUND";
        if (health == null) health = "UNKNOWN";
    }
}
