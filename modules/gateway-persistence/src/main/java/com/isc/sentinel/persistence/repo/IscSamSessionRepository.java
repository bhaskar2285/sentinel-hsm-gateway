package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IscSamSessionRepository extends JpaRepository<IscSamSession, Long> {
    Optional<IscSamSession> findBySessionToken(String sessionToken);
}
