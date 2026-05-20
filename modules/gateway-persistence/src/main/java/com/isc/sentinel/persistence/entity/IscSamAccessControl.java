package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_sam_accesscontrol")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamAccessControl extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "sam_role_id",   nullable = false) private Long samRoleId;
    @Column(name = "sam_menu_id",   nullable = false) private Long samMenuId;
    @Column(name = "sam_action_id", nullable = false) private Long samActionId;
}
