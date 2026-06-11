package com.isc.sentinel.api.command.impl;

import com.isc.sentinel.api.command.ThalesCommandService;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PECommandService implements ThalesCommandService {
    @Override public String commandCode() { return "PE"; }
    @Override
    public Map<String, Object> execute(Map<String, Object> params) {
        return Map.of("errCode", "68", "message", "Command not yet implemented");
    }
}
