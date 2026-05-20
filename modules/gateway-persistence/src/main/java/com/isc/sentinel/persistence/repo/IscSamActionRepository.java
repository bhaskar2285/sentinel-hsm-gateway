package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamAction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IscSamActionRepository extends JpaRepository<IscSamAction, Long> {
    Optional<IscSamAction> findByName(String name);
}
