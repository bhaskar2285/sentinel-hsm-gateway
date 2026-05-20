package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_ms_branch")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscMsBranch extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "bank_rec_id", nullable = false)
    private Long bankRecId;

    @Column(nullable = false, length = 20)
    private String code;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(length = 100)
    private String description;

    @Column(name = "short_code", length = 6)
    private String shortCode;

    @Column(length = 50)
    private String city;

    @Column(length = 50)
    private String region;

    @Column(name = "country_iso2", length = 2)
    private String countryIso2;
}
