package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "isc_sam_session")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "sam_staff_id", nullable = false) private Long samStaffId;

    @Column(name = "session_token", nullable = false, length = 255, unique = true)
    private String sessionToken;

    @Column(name = "ip_address",  length = 45)  private String ipAddress;
    @Column(name = "user_agent",  length = 512) private String userAgent;
    @Column(name = "login_at",    nullable = false) private LocalDateTime loginAt;
    @Column(name = "last_seen_at",nullable = false) private LocalDateTime lastSeenAt;
    @Column(name = "expires_at",  nullable = false) private LocalDateTime expiresAt;
    @Column(name = "logout_at")                  private LocalDateTime logoutAt;
    @Column(name = "record_status", nullable = false, length = 1) private String recordStatus;

    @PrePersist
    void onInsert() {
        LocalDateTime now = LocalDateTime.now();
        if (loginAt    == null) loginAt    = now;
        if (lastSeenAt == null) lastSeenAt = now;
        if (recordStatus == null) recordStatus = "Y";
    }
}
