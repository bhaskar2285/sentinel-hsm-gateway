package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamAccessControl;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IscSamAccessControlRepository extends JpaRepository<IscSamAccessControl, Long> {
    List<IscSamAccessControl> findBySamRoleId(Long samRoleId);
}
