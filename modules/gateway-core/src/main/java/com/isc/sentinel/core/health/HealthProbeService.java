package com.isc.sentinel.core.health;

import com.isc.sentinel.persistence.entity.HsmNode;
import com.isc.sentinel.persistence.repo.HsmNodeRepository;
import com.isc.sentinel.spi.HsmNodeRef;
import com.isc.sentinel.spi.HsmVendor;
import com.isc.sentinel.spi.HsmVendorAdapter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Periodically pings every enabled HSM node via its vendor adapter and updates health/lastSeen.
 */
@Slf4j
@Service
public class HealthProbeService {

    private final HsmNodeRepository nodeRepo;
    private final Map<HsmVendor, HsmVendorAdapter> adapters;

    public HealthProbeService(HsmNodeRepository nodeRepo, List<HsmVendorAdapter> adapterList) {
        this.nodeRepo = nodeRepo;
        this.adapters = adapterList.stream().collect(Collectors.toMap(HsmVendorAdapter::vendor, a -> a));
    }

    @Scheduled(initialDelayString = "PT5S", fixedDelayString = "PT15S")
    public void probe() {
        List<HsmNode> nodes = nodeRepo.findAll();
        for (HsmNode n : nodes) {
            if (!Boolean.TRUE.equals(n.getEnabled())) continue;
            HsmVendor vendor;
            try { vendor = HsmVendor.valueOf(n.getVendor()); }
            catch (Exception e) { continue; }

            HsmVendorAdapter adapter = adapters.get(vendor);
            if (adapter == null) continue;

            HsmNodeRef ref = HsmNodeRef.builder()
                .id(n.getId())
                .vendor(vendor)
                .host(n.getHost())
                .port(n.getPort())
                .weight(n.getWeight())
                .direction(n.getDirection())
                .build();

            boolean up;
            try { up = adapter.health(ref); }
            catch (Exception e) { up = false; }

            String newHealth = up ? "UP" : "DOWN";
            if (!newHealth.equals(n.getHealth())) {
                log.info("HSM node {} ({}:{}) health: {} -> {}", n.getId(), n.getHost(), n.getPort(), n.getHealth(), newHealth);
            }
            n.setHealth(newHealth);
            if (up) n.setLastSeen(OffsetDateTime.now());
            nodeRepo.save(n);
        }
    }
}
