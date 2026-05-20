package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_sam_team")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamTeam extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "ms_bank_id", nullable = false)
    private Long msBankId;

    @Column(name = "team_code", nullable = false, length = 20)
    private String teamCode;

    @Column(name = "team_name", nullable = false, length = 50)
    private String teamName;
}
