package com.isc.sentinel.api.command.impl;

import com.isc.sentinel.api.command.ThalesCommandService;
import com.isc.sentinel.core.dispatch.CommandDispatcher;
import com.isc.sentinel.spi.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class EECommandService implements ThalesCommandService {
    private final CommandDispatcher dispatcher;
    @Override public String commandCode() { return "EE"; }
    @Override
    public Map<String, Object> execute(Map<String, Object> params) {
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_DERIVE_IBM).vendorHint(HsmVendor.THALES).params(params).build());
        Map<String, Object> out = new HashMap<>(r.getResult());
        out.put("errCode", r.getErrCode()); out.put("status", r.getStatus());
        if (r.getErrText() != null) out.put("errText", r.getErrText());
        return out;
    }
}
