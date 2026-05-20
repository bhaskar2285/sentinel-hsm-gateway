package com.isc.sentinel.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * ISC standard 15-column audit template.
 * Inherited by all isc_ms_* / isc_sam_* business entities.
 *
 * Convention: record_status CHAR(1) — 'Y'=active, 'N'=deleted, 'P'=pending.
 * record_created_* stamped on insert; record_updated_* refreshed on every update.
 */
@MappedSuperclass
@Getter @Setter
public abstract class IscAuditable {

    @Column(name = "record_status", nullable = false, columnDefinition = "char(1)")
    private String recordStatus;

    @Column(name = "record_created_date",       nullable = false)        private LocalDateTime recordCreatedDate;
    @Column(name = "record_created_id",         nullable = false)        private Integer       recordCreatedId;
    @Column(name = "record_created_name",       nullable = false, length = 50)  private String recordCreatedName;
    @Column(name = "record_created_team_code",  nullable = false, length = 20)  private String recordCreatedTeamCode;
    @Column(name = "record_created_team_name",  nullable = false, length = 50)  private String recordCreatedTeamName;
    @Column(name = "record_created_bank_code",  nullable = false, length = 20)  private String recordCreatedBankCode;
    @Column(name = "record_created_bank_name",  nullable = false, length = 50)  private String recordCreatedBankName;

    @Column(name = "record_updated_date",       nullable = false)        private LocalDateTime recordUpdatedDate;
    @Column(name = "record_updated_id",         nullable = false)        private Integer       recordUpdatedId;
    @Column(name = "record_updated_name",       nullable = false, length = 50)  private String recordUpdatedName;
    @Column(name = "record_updated_team_code",  nullable = false, length = 20)  private String recordUpdatedTeamCode;
    @Column(name = "record_updated_team_name",  nullable = false, length = 50)  private String recordUpdatedTeamName;
    @Column(name = "record_updated_bank_code",  nullable = false, length = 20)  private String recordUpdatedBankCode;
    @Column(name = "record_updated_bank_name",  nullable = false, length = 50)  private String recordUpdatedBankName;

    @PrePersist
    void onInsert() {
        LocalDateTime now = LocalDateTime.now();
        if (recordStatus == null)            recordStatus = "Y";
        if (recordCreatedDate == null)       recordCreatedDate = now;
        if (recordCreatedId == null)         recordCreatedId = 0;
        if (recordCreatedName == null)       recordCreatedName = "SYSTEM";
        if (recordCreatedTeamCode == null)   recordCreatedTeamCode = "SYSTEM";
        if (recordCreatedTeamName == null)   recordCreatedTeamName = "SYSTEM";
        if (recordCreatedBankCode == null)   recordCreatedBankCode = "ISC";
        if (recordCreatedBankName == null)   recordCreatedBankName = "ISC";
        if (recordUpdatedDate == null)       recordUpdatedDate = now;
        if (recordUpdatedId == null)         recordUpdatedId = 0;
        if (recordUpdatedName == null)       recordUpdatedName = recordCreatedName;
        if (recordUpdatedTeamCode == null)   recordUpdatedTeamCode = recordCreatedTeamCode;
        if (recordUpdatedTeamName == null)   recordUpdatedTeamName = recordCreatedTeamName;
        if (recordUpdatedBankCode == null)   recordUpdatedBankCode = recordCreatedBankCode;
        if (recordUpdatedBankName == null)   recordUpdatedBankName = recordCreatedBankName;
    }

    @PreUpdate
    void onUpdate() {
        recordUpdatedDate = LocalDateTime.now();
    }
}
