package com.isc.sentinel.api.controller;

import com.isc.sentinel.persistence.entity.HsmNode;
import com.isc.sentinel.persistence.entity.HsmPool;
import com.isc.sentinel.persistence.repo.HsmNodeRepository;
import com.isc.sentinel.persistence.repo.HsmPoolRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AdminController {

    private final HsmPoolRepository poolRepo;
    private final HsmNodeRepository nodeRepo;

    @GetMapping("/pools")
    @PreAuthorize("hasAuthority('OP_ADMIN_POOL') or hasAuthority('OP_KEY_READ')")
    public List<HsmPool> pools() {
        return poolRepo.findAll();
    }

    @GetMapping("/hsms")
    @PreAuthorize("hasAuthority('OP_ADMIN_POOL') or hasAuthority('OP_KEY_READ')")
    public List<HsmNode> hsms() {
        return nodeRepo.findAll();
    }

    @PostMapping("/hsms/{id}/drain")
    @PreAuthorize("hasAuthority('OP_ADMIN_POOL')")
    public HsmNode drain(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setHealth("DRAINING");
        return nodeRepo.save(n);
    }

    @PostMapping("/hsms/{id}/enable")
    @PreAuthorize("hasAuthority('OP_ADMIN_POOL')")
    public HsmNode enable(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setEnabled(true);
        n.setHealth("UNKNOWN");
        return nodeRepo.save(n);
    }

    @PostMapping("/hsms/{id}/disable")
    @PreAuthorize("hasAuthority('OP_ADMIN_POOL')")
    public HsmNode disable(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setEnabled(false);
        return nodeRepo.save(n);
    }
}
