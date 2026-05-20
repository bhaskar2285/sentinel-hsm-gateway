package com.isc.sentinel.core.lb;

import com.isc.sentinel.persistence.entity.HsmNode;
import com.isc.sentinel.persistence.entity.HsmPool;
import com.isc.sentinel.persistence.repo.HsmNodeRepository;
import com.isc.sentinel.persistence.repo.HsmPoolRepository;
import com.isc.sentinel.spi.HsmNodeRef;
import com.isc.sentinel.spi.HsmVendor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Vendor-aware load balancer. Same-vendor pools only.
 * Routes to a healthy node within the matching pool.
 */
@Component
@RequiredArgsConstructor
public class PoolRouter {

    private final HsmPoolRepository poolRepo;
    private final HsmNodeRepository nodeRepo;

    private final ConcurrentHashMap<Long, AtomicInteger> rrCounters = new ConcurrentHashMap<>();

    public Optional<HsmNodeRef> route(HsmVendor vendor, String stickyKey) {
        List<HsmPool> pools = poolRepo.findByVendorAndEnabledTrue(vendor.name());
        if (pools.isEmpty()) return Optional.empty();
        HsmPool pool = pools.get(0); // simplistic — first enabled pool per vendor

        List<HsmNode> nodes = nodeRepo.findByPoolIdAndEnabledTrue(pool.getId())
            .stream()
            .filter(n -> "UP".equals(n.getHealth()) || "UNKNOWN".equals(n.getHealth()))
            .toList();

        if (nodes.isEmpty()) return Optional.empty();

        HsmNode chosen = switch (LoadBalanceStrategy.valueOf(pool.getLbStrategy())) {
            case ROUND_ROBIN -> nodes.get(nextRR(pool.getId(), nodes.size()));
            case WEIGHTED    -> weighted(nodes);
            case LEAST_CONN  -> nodes.get(0);  // TODO track conn counts
            case STICKY_KEY  -> nodes.get(Math.abs((stickyKey == null ? 0 : stickyKey.hashCode())) % nodes.size());
        };

        return Optional.of(HsmNodeRef.builder()
            .id(chosen.getId())
            .vendor(HsmVendor.valueOf(chosen.getVendor()))
            .host(chosen.getHost())
            .port(chosen.getPort())
            .weight(chosen.getWeight())
            .direction(chosen.getDirection())
            .build());
    }

    private int nextRR(Long poolId, int size) {
        return rrCounters.computeIfAbsent(poolId, k -> new AtomicInteger(0)).getAndIncrement() & 0x7FFFFFFF % size;
    }

    private HsmNode weighted(List<HsmNode> nodes) {
        int total = nodes.stream().mapToInt(HsmNode::getWeight).sum();
        int r = (int) (Math.random() * total);
        int cum = 0;
        for (HsmNode n : nodes) {
            cum += n.getWeight();
            if (r < cum) return n;
        }
        return nodes.getLast();
    }
}
