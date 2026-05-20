package com.isc.sentinel.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Converts JWT → granted authorities.
 *  - reads "sub" + optional "roles" claim
 *  - resolves user roles + role→op mapping from rbac_user_role / rbac_role_op
 *  - emits authorities as "OP_<opCode>" + "ROLE_<roleName>"
 */
@Component
public class RbacJwtConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final JdbcTemplate jdbc;

    public RbacJwtConverter(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String userId = jwt.getSubject();
        Set<GrantedAuthority> auths = new HashSet<>();

        // Claim-based roles (issuer may provide)
        Object roles = jwt.getClaim("roles");
        if (roles instanceof Collection<?> coll) {
            coll.forEach(r -> auths.add(new SimpleGrantedAuthority("ROLE_" + r)));
        }

        // DB-based role/op resolution
        if (userId != null) {
            List<String> userRoles = jdbc.queryForList(
                "SELECT r.name FROM rbac_user_role ur JOIN rbac_role r ON r.id = ur.role_id WHERE ur.user_id = ?",
                String.class, userId);
            userRoles.forEach(r -> auths.add(new SimpleGrantedAuthority("ROLE_" + r)));

            if (!userRoles.isEmpty()) {
                String inClause = userRoles.stream().map(r -> "?").collect(Collectors.joining(","));
                List<String> ops = jdbc.queryForList(
                    "SELECT DISTINCT ro.op FROM rbac_role_op ro JOIN rbac_role r ON r.id = ro.role_id WHERE r.name IN (" + inClause + ")",
                    String.class, userRoles.toArray());
                ops.forEach(op -> auths.add(new SimpleGrantedAuthority("OP_" + op)));
            }
        }
        return auths;
    }
}
