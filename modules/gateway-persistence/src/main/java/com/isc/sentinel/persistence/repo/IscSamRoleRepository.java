package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IscSamRoleRepository extends JpaRepository<IscSamRole, Long> {
    List<IscSamRole> findByMsBankId(Long msBankId);
    Optional<IscSamRole> findByMsBankIdAndRoleName(Long msBankId, String roleName);
}
