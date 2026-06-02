package com.isc.sentinel.api.controller;

import com.isc.sentinel.persistence.entity.HsmNode;
import com.isc.sentinel.persistence.entity.HsmPool;
import com.isc.sentinel.persistence.repo.HsmNodeRepository;
import com.isc.sentinel.persistence.repo.HsmPoolRepository;
import com.isc.sentinel.vendor.thales.ThalesVendorAdapter;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AdminController {

    private final HsmPoolRepository    poolRepo;
    private final HsmNodeRepository    nodeRepo;
    private final ThalesVendorAdapter  thalesAdapter;

    @Data
    public static class NodeRequest {
        private Long   poolId;
        private String vendor;
        private String host;
        private Integer port;
        private Integer weight;
        private String direction;
        private Boolean enabled;
    }

    @GetMapping("/pools")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('OP_KEY_READ')")
    public List<HsmPool> pools() {
        return poolRepo.findAll();
    }

    @GetMapping("/hsms")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('OP_KEY_READ')")
    public List<HsmNode> hsms() {
        return nodeRepo.findAll();
    }

    @PostMapping("/hsms")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    public HsmNode createNode(@RequestBody NodeRequest req) {
        if (req.getHost() == null || req.getPort() == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "host and port required");
        HsmNode n = new HsmNode();
        n.setPoolId(req.getPoolId() != null ? req.getPoolId() : 1L);
        n.setVendor(req.getVendor() != null ? req.getVendor() : "THALES");
        n.setHost(req.getHost());
        n.setPort(req.getPort());
        n.setWeight(req.getWeight() != null ? req.getWeight() : 1);
        n.setDirection(req.getDirection() != null ? req.getDirection() : "OUTBOUND");
        n.setEnabled(req.getEnabled() != null ? req.getEnabled() : true);
        return nodeRepo.save(n);
    }

    @PutMapping("/hsms/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public HsmNode updateNode(@PathVariable Long id, @RequestBody NodeRequest req) {
        HsmNode n = nodeRepo.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (req.getHost() != null)      n.setHost(req.getHost());
        if (req.getPort() != null)      n.setPort(req.getPort());
        if (req.getWeight() != null)    n.setWeight(req.getWeight());
        if (req.getVendor() != null)    n.setVendor(req.getVendor());
        if (req.getEnabled() != null)   n.setEnabled(req.getEnabled());
        if (req.getDirection() != null) n.setDirection(req.getDirection());
        n.setHealth("UNKNOWN");
        HsmNode saved = nodeRepo.save(n);
        thalesAdapter.reloadNode(id);
        return saved;
    }

    @DeleteMapping("/hsms/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteNode(@PathVariable Long id) {
        if (!nodeRepo.existsById(id))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        thalesAdapter.reloadNode(id);
        nodeRepo.deleteById(id);
    }

    @PostMapping("/hsms/{id}/drain")
    @PreAuthorize("hasRole('ADMIN')")
    public HsmNode drain(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setHealth("DRAINING");
        return nodeRepo.save(n);
    }

    @PostMapping("/hsms/{id}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public HsmNode enable(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setEnabled(true);
        n.setHealth("UNKNOWN");
        return nodeRepo.save(n);
    }

    @PostMapping("/hsms/{id}/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public HsmNode disable(@PathVariable Long id) {
        HsmNode n = nodeRepo.findById(id).orElseThrow();
        n.setEnabled(false);
        return nodeRepo.save(n);
    }
}
