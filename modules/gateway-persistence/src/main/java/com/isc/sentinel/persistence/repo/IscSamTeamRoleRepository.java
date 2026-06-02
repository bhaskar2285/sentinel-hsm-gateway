package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamTeamRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IscSamTeamRoleRepository extends JpaRepository<IscSamTeamRole, Long> {
    List<IscSamTeamRole> findBySamTeamId(Long samTeamId);
    boolean existsBySamTeamIdAndSamRoleId(Long samTeamId, Long samRoleId);
}
