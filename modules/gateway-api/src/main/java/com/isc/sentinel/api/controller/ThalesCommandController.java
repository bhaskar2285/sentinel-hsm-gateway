package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.command.ThalesCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/thales/command")
public class ThalesCommandController {

    private final Map<String, ThalesCommandService> servicesByCode;

    public ThalesCommandController(List<ThalesCommandService> services) {
        this.servicesByCode = services.stream()
            .collect(Collectors.toMap(
                s -> s.commandCode().toUpperCase(),
                Function.identity()
            ));
    }

    @PostMapping("/{cmd}")
    @PreAuthorize("hasAuthority('OP_RAW_CMD')")
    public ResponseEntity<Map<String, Object>> execute(
            @PathVariable String cmd,
            @RequestBody(required = false) Map<String, Object> params) {
        String code = cmd.toUpperCase();
        ThalesCommandService svc = servicesByCode.get(code);
        if (svc == null) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> body = params != null ? params : Map.of();
        Map<String, Object> result = svc.execute(body);
        return ResponseEntity.ok(result);
    }
}
