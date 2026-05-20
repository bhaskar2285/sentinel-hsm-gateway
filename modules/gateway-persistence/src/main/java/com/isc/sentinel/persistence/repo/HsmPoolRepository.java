package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.HsmPool;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HsmPoolRepository extends JpaRepository<HsmPool, Long> {
    Optional<HsmPool> findByName(String name);
    List<HsmPool> findByVendorAndEnabledTrue(String vendor);
}
