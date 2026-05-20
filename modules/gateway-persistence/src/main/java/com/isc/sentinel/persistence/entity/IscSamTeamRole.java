package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_sam_team_role")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamTeamRole extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "sam_team_id", nullable = false) private Long samTeamId;
    @Column(name = "sam_role_id", nullable = false) private Long samRoleId;
}
