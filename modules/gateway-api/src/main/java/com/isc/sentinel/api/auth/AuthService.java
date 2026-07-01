package com.isc.sentinel.api.auth;

import com.isc.sentinel.persistence.entity.IscMsBank;
import com.isc.sentinel.persistence.entity.IscSamSession;
import com.isc.sentinel.persistence.entity.IscSamStaff;
import com.isc.sentinel.persistence.repo.IscMsBankRepository;
import com.isc.sentinel.persistence.repo.IscSamSessionRepository;
import com.isc.sentinel.persistence.repo.IscSamStaffRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Per-bank authentication. Routes based on isc_ms_bank.login_method_type:
 *   DB   → bcrypt-style check against isc_sam_staff.staff_loginpwd
 *   LDAP → JNDI bind to ldap_ip:ldap_port using base_dn/search_base_dn
 *   MSAD → JNDI bind with userPrincipalName upn convention
 *   OIDC → external IdP redirect (Phase 2, falls through to error here)
 *
 * On success: creates isc_sam_session row, returns opaque session token.
 * On failure: increments bad_loginpwd_count, locks at 5.
 *
 * Password hashing here = SHA-256(salt || pwd). Production would use bcrypt/argon2.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final IscSamStaffRepository   staffRepo;
    private final IscMsBankRepository     bankRepo;
    private final IscSamSessionRepository sessionRepo;
    private final SecureRandom rnd = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of().withLowerCase();

    public AuthResult login(String loginname, String password, String ip, String userAgent) {
        Optional<IscSamStaff> staffOpt = staffRepo.findByStaffLoginname(loginname);
        if (staffOpt.isEmpty()) return AuthResult.fail("unknown user");

        IscSamStaff staff = staffOpt.get();
        if (!"ACTIVE".equals(staff.getUserStatusCode())) {
            return AuthResult.fail("account " + staff.getUserStatusCode().toLowerCase());
        }
        if (staff.getBadLoginpwdCount() != null && staff.getBadLoginpwdCount() >= 5) {
            return AuthResult.fail("account locked");
        }

        IscMsBank bank = bankRepo.findById(staff.getMsBankId())
            .orElseThrow(() -> new IllegalStateException("bank missing for staff " + loginname));

        boolean ok = switch (bank.getLoginMethodType()) {
            case "DB"        -> verifyDb(staff, password);
            case "LDAP"      -> LdapAuthStrategy.bind(bank, loginname, password);
            case "MSAD"      -> LdapAuthStrategy.bindMsAd(bank, loginname, password);
            default          -> false;
        };

        if (!ok) {
            int count = (staff.getBadLoginpwdCount() == null ? 0 : staff.getBadLoginpwdCount()) + 1;
            staff.setBadLoginpwdCount(count);
            if (count >= 5) {
                staff.setUserStatusCode("LOCKED");
                staff.setLockedDateTime(LocalDateTime.now());
            }
            staffRepo.save(staff);
            return AuthResult.fail("invalid credentials");
        }

        staff.setBadLoginpwdCount(0);
        staff.setLastLoginDateTime(LocalDateTime.now());
        staffRepo.save(staff);

        byte[] tokenBytes = new byte[32];
        rnd.nextBytes(tokenBytes);
        String token = HEX.formatHex(tokenBytes);

        IscSamSession session = IscSamSession.builder()
            .samStaffId(staff.getRecId())
            .sessionToken(token)
            .ipAddress(ip)
            .userAgent(userAgent)
            .expiresAt(LocalDateTime.now().plusHours(1))
            .build();
        sessionRepo.save(session);

        log.info("login OK loginname={} bank={} method={}",
            loginname, bank.getCode(), bank.getLoginMethodType());

        return AuthResult.ok(token, staff.getRecId(), staff.getMsBankId(), bank.getCode());
    }

    public void logout(String token) {
        sessionRepo.findBySessionToken(token).ifPresent(s -> {
            s.setLogoutAt(LocalDateTime.now());
            s.setRecordStatus("N");
            sessionRepo.save(s);
        });
    }

    /** DB strategy: SHA-256(staff_loginname || password) hex against stored hash. */
    private boolean verifyDb(IscSamStaff staff, String password) {
        if (staff.getStaffLoginpwd() == null || staff.getStaffLoginpwd().isEmpty()) return false;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((staff.getStaffLoginname() + ":" + password).getBytes());
            String hashed = HEX.formatHex(digest);
            return hashed.equals(staff.getStaffLoginpwd());
        } catch (Exception e) {
            return false;
        }
    }

    /** Hash a plaintext password using the DB strategy (for seed / admin reset). */
    public static String hashDb(String loginname, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((loginname + ":" + password).getBytes());
            return HEX.formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
