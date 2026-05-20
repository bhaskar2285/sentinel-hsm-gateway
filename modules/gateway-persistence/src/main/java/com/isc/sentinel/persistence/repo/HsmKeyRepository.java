package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.HsmKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface HsmKeyRepository extends JpaRepository<HsmKey, Long> {
    Optional<HsmKey> findByKeyUuid(UUID keyUuid);
    Optional<HsmKey> findByLabel(String label);
}
