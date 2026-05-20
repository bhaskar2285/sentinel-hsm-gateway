package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.HsmCommandAudit;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HsmCommandAuditRepository extends JpaRepository<HsmCommandAudit, Long> {
}
