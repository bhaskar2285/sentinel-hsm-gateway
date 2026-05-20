package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "isc_sam_staff")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IscSamStaff extends IscAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rec_id")
    private Long recId;

    @Column(name = "staff_fname", nullable = false, length = 50)
    private String staffFname;

    @Column(name = "staff_lname", nullable = false, length = 50)
    private String staffLname;

    @Column(name = "staff_email", length = 255)
    private String staffEmail;

    @Column(name = "ms_bank_id", nullable = false)
    private Long msBankId;

    @Column(name = "ms_branch_id")
    private Long msBranchId;

    @Column(name = "sam_team_id", nullable = false)
    private Long samTeamId;

    @Column(name = "staff_loginname", nullable = false, length = 64, unique = true)
    private String staffLoginname;

    @Column(name = "staff_loginpwd", length = 1024)
    private String staffLoginpwd;                   // bcrypt; null for LDAP-bound

    @Column(name = "last_updated_loginpwd", length = 8)
    private String lastUpdatedLoginpwd;

    @Column(name = "bad_loginpwd_count", nullable = false)
    private Integer badLoginpwdCount;

    @Column(name = "user_status_code", nullable = false, length = 20)
    private String userStatusCode;                   // ACTIVE | LOCKED | INACTIVE | EXPIRED

    @Column(name = "activated_date_time")
    private LocalDateTime activatedDateTime;

    @Column(name = "inactivated_date_time")
    private LocalDateTime inactivatedDateTime;

    @Column(name = "locked_date_time")
    private LocalDateTime lockedDateTime;

    @Column(name = "expiried_date_time")
    private LocalDateTime expiriedDateTime;          // sic — matches Thailand schema typo

    @Column(name = "last_login_date_time")
    private LocalDateTime lastLoginDateTime;

    @Column(name = "employee_code", length = 20)
    private String employeeCode;

    @Column(name = "force_change_pwd_flag", nullable = false, length = 1)
    private String forceChangePwdFlag;

    @Column(name = "lk_otp_type_code", length = 20)
    private String lkOtpTypeCode;

    @Column(name = "otp_no", length = 1024)
    private String otpNo;
}
