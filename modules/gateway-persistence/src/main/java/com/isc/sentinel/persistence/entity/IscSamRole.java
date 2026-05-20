package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_sam_role")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamRole extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "ms_bank_id", nullable = false)
    private Long msBankId;

    @Column(name = "role_name", nullable = false, length = 50)
    private String roleName;

    @Column(length = 255)
    private String description;
}
