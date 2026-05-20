package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.HsmNode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface HsmNodeRepository extends JpaRepository<HsmNode, Long> {
    List<HsmNode> findByPoolIdAndEnabledTrue(Long poolId);
    List<HsmNode> findByVendorAndEnabledTrue(String vendor);
}
