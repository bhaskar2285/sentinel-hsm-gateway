package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscMsBranch;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IscMsBranchRepository extends JpaRepository<IscMsBranch, Long> {
    List<IscMsBranch> findByBankRecId(Long bankRecId);
    Optional<IscMsBranch> findByBankRecIdAndCode(Long bankRecId, String code);
}
