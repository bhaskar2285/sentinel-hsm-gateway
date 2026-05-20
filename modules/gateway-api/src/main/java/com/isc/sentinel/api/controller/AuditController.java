package com.isc.sentinel.api.controller;

import com.isc.sentinel.persistence.entity.HsmCommandAudit;
import com.isc.sentinel.persistence.repo.HsmCommandAuditRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final HsmCommandAuditRepository auditRepo;

    @GetMapping
    public Page<HsmCommandAudit> search(
        @RequestParam(required = false) String op,
        @RequestParam(required = false) String userId,
        @RequestParam(required = false) String status,
        @RequestParam(required = false) String vendor,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime from,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime to,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "50") int size
    ) {
        return auditRepo.search(emptyToNull(op), emptyToNull(userId), emptyToNull(status), emptyToNull(vendor),
            from, to, PageRequest.of(page, Math.min(size, 200)));
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
