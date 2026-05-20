package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamTeam;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IscSamTeamRepository extends JpaRepository<IscSamTeam, Long> {
    List<IscSamTeam> findByMsBankId(Long msBankId);
    Optional<IscSamTeam> findByMsBankIdAndTeamCode(Long msBankId, String teamCode);
}
