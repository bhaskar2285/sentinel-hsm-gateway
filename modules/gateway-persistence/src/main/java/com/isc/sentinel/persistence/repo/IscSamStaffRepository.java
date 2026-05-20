package com.isc.sentinel.persistence.repo;

import com.isc.sentinel.persistence.entity.IscSamStaff;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IscSamStaffRepository extends JpaRepository<IscSamStaff, Long> {
    Optional<IscSamStaff> findByStaffLoginname(String staffLoginname);
    List<IscSamStaff>     findByMsBankId(Long msBankId);
}
