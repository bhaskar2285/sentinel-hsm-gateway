package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "isc_ms_bank")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscMsBank extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(nullable = false, length = 20, unique = true)
    private String code;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(length = 100)
    private String description;

    @Column(name = "short_code", length = 6)
    private String shortCode;

    @Column(length = 10)
    private String fiid;

    @Column(name = "is_default", length = 1)
    private String isDefault;

    @Column(name = "login_method_type", nullable = false, length = 10)
    private String loginMethodType;          // DB | LDAP | MSAD | OIDC

    @Column(name = "ldap_ip", length = 20)
    private String ldapIp;

    @Column(name = "ldap_port")
    private Integer ldapPort;

    @Column(name = "base_dn", length = 100)
    private String baseDn;

    @Column(name = "search_base_dn", length = 50)
    private String searchBaseDn;

    @Column(name = "permission_method_type", nullable = false, length = 10)
    private String permissionMethodType;     // DB | LDAP | IDM

    @Column(name = "idm_ip", length = 20)
    private String idmIp;

    @Column(name = "idm_port")
    private Integer idmPort;

    @Column(name = "country_iso2", length = 2)
    private String countryIso2;

    @Column(name = "swift_bic", length = 11)
    private String swiftBic;

    @Column(name = "regulator_id", length = 64)
    private String regulatorId;
}
