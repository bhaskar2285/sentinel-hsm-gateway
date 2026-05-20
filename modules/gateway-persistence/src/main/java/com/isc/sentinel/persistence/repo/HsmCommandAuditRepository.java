package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.HsmCommandAudit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;

public interface HsmCommandAuditRepository extends JpaRepository<HsmCommandAudit, Long> {

    @Query(value = """
        SELECT * FROM hsm_command_audit
        WHERE (CAST(:op       AS varchar) IS NULL OR op       = :op)
          AND (CAST(:userId   AS varchar) IS NULL OR user_id  = :userId)
          AND (CAST(:status   AS varchar) IS NULL OR status   = :status)
          AND (CAST(:vendor   AS varchar) IS NULL OR vendor   = :vendor)
          AND (CAST(:fromTs   AS timestamptz) IS NULL OR ts >= :fromTs)
          AND (CAST(:toTs     AS timestamptz) IS NULL OR ts <= :toTs)
        ORDER BY ts DESC
        """, nativeQuery = true)
    Page<HsmCommandAudit> search(
        @Param("op")     String op,
        @Param("userId") String userId,
        @Param("status") String status,
        @Param("vendor") String vendor,
        @Param("fromTs") OffsetDateTime fromTs,
        @Param("toTs")   OffsetDateTime toTs,
        Pageable page);
}
