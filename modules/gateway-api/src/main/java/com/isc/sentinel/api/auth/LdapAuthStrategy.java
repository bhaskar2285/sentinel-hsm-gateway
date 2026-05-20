package com.isc.sentinel.api.auth;

import com.isc.sentinel.persistence.entity.IscMsBank;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * JNDI-based LDAP bind authentication.
 * Per-bank LDAP config sourced from isc_ms_bank.{ldap_ip, ldap_port, base_dn, search_base_dn}.
 *
 * Two bind styles:
 *   LDAP  → distinguished-name bind: "uid=<user>,<searchBaseDn>,<baseDn>"
 *   MSAD  → userPrincipalName bind:  "<user>@<baseDn-as-domain>"
 *
 * Success = LDAP server accepts the bind (no exception). Failure = AuthenticationException
 * or any NamingException. TLS used when ldap_port=636 (LDAPS) — plain LDAP on 389.
 */
public final class LdapAuthStrategy {

    private LdapAuthStrategy() {}

    public static boolean bind(IscMsBank bank, String username, String password) {
        if (bank.getLdapIp() == null || bank.getLdapPort() == null) return false;
        String scheme = (bank.getLdapPort() == 636) ? "ldaps" : "ldap";
        String url    = scheme + "://" + bank.getLdapIp() + ":" + bank.getLdapPort();

        String dn;
        if (bank.getSearchBaseDn() != null && !bank.getSearchBaseDn().isEmpty()) {
            dn = "uid=" + username + "," + bank.getSearchBaseDn() + "," + bank.getBaseDn();
        } else {
            dn = "uid=" + username + "," + bank.getBaseDn();
        }
        return tryBind(url, dn, password);
    }

    public static boolean bindMsAd(IscMsBank bank, String username, String password) {
        if (bank.getLdapIp() == null || bank.getLdapPort() == null) return false;
        String scheme = (bank.getLdapPort() == 636) ? "ldaps" : "ldap";
        String url    = scheme + "://" + bank.getLdapIp() + ":" + bank.getLdapPort();

        // Convert "dc=foo,dc=bar" → "foo.bar"
        String domain = bank.getBaseDn() == null ? "" :
            bank.getBaseDn().replaceAll("(?i)dc=", "").replace(",", ".");
        String upn = username + "@" + domain;
        return tryBind(url, upn, password);
    }

    private static boolean tryBind(String url, String dn, String password) {
        if (password == null || password.isEmpty()) return false;
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put("com.sun.jndi.ldap.connect.timeout", "5000");
        env.put("com.sun.jndi.ldap.read.timeout", "5000");

        try {
            InitialDirContext ctx = new InitialDirContext(env);
            ctx.close();
            return true;
        } catch (AuthenticationException ae) {
            return false;
        } catch (NamingException ne) {
            return false;
        }
    }
}
