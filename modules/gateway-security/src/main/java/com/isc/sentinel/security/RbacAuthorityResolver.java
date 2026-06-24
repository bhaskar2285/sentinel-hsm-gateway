package com.isc.sentinel.security;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves a staff member's granted authorities from the ISC SAM (V3) schema.
 *
 * Authority chain:
 *   isc_sam_staff.sam_team_id
 *     -> isc_sam_team_role  (team -> role)
 *       -> isc_sam_role            => ROLE_&lt;role_name&gt;
 *       -> isc_sam_accesscontrol   (role -> action)
 *         -> isc_sam_action.name   => OP_&lt;action_name&gt;
 *
 * Replaces the legacy RbacJwtConverter, which queried rbac_user_role /
 * rbac_role / rbac_role_op — all dropped in migration V3.
 */
@Component
public class RbacAuthorityResolver {

    private static final String SQL_ROLES = """
        SELECT DISTINCT r.role_name
        FROM isc_sam_staff s
        JOIN isc_sam_team_role tr ON tr.sam_team_id = s.sam_team_id AND tr.record_status = 'Y'
        JOIN isc_sam_role r       ON r.rec_id = tr.sam_role_id     AND r.record_status = 'Y'
        WHERE s.rec_id = ? AND s.record_status = 'Y'
        """;

    private static final String SQL_OPS = """
        SELECT DISTINCT a.name
        FROM isc_sam_staff s
        JOIN isc_sam_team_role tr      ON tr.sam_team_id = s.sam_team_id  AND tr.record_status = 'Y'
        JOIN isc_sam_accesscontrol ac  ON ac.sam_role_id = tr.sam_role_id AND ac.record_status = 'Y'
        JOIN isc_sam_action a          ON a.rec_id = ac.sam_action_id     AND a.record_status = 'Y'
        WHERE s.rec_id = ? AND s.record_status = 'Y'
        """;

    private final JdbcTemplate jdbc;

    public RbacAuthorityResolver(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** All ROLE_* and OP_* authorities granted to the given staff record id. */
    public Set<GrantedAuthority> resolve(long staffId) {
        Set<GrantedAuthority> auths = new HashSet<>();

        List<String> roles = jdbc.queryForList(SQL_ROLES, String.class, staffId);
        roles.forEach(r -> auths.add(new SimpleGrantedAuthority("ROLE_" + r)));

        List<String> ops = jdbc.queryForList(SQL_OPS, String.class, staffId);
        ops.forEach(op -> auths.add(new SimpleGrantedAuthority("OP_" + op)));

        return auths;
    }
}
