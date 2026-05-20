package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscMsBank;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IscMsBankRepository extends JpaRepository<IscMsBank, Long> {
    Optional<IscMsBank> findByCode(String code);
    Optional<IscMsBank> findByFiid(String fiid);
}
