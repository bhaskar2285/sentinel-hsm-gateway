package com.isc.sentinel.api.command;

import java.util.Map;

public interface ThalesCommandService {
    String commandCode();
    Map<String, Object> execute(Map<String, Object> params);
}
