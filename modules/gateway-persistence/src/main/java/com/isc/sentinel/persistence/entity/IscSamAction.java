package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_sam_action")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamAction extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(nullable = false, length = 50, unique = true)
    private String name;

    @Column(length = 255)
    private String description;
}
