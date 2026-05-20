package com.isc.sentinel.api.auth;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class AuthResult {
    boolean success;
    String  reason;
    String  token;
    Long    staffId;
    Long    bankId;
    String  bankCode;

    public static AuthResult ok(String token, Long staffId, Long bankId, String bankCode) {
        return AuthResult.builder().success(true).token(token).staffId(staffId).bankId(bankId).bankCode(bankCode).build();
    }
    public static AuthResult fail(String reason) {
        return AuthResult.builder().success(false).reason(reason).build();
    }
}
