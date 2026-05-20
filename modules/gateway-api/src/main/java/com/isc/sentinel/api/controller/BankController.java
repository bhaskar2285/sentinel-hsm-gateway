package com.isc.sentinel.api.controller;

import com.isc.sentinel.persistence.entity.IscMsBank;
import com.isc.sentinel.persistence.entity.IscMsBranch;
import com.isc.sentinel.persistence.repo.IscMsBankRepository;
import com.isc.sentinel.persistence.repo.IscMsBranchRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class BankController {

    private final IscMsBankRepository   bankRepo;
    private final IscMsBranchRepository branchRepo;

    // ---- banks ----

    @GetMapping("/banks")
    public List<IscMsBank> listBanks() {
        return bankRepo.findAll();
    }

    @GetMapping("/banks/{id}")
    public ResponseEntity<IscMsBank> getBank(@PathVariable Long id) {
        return bankRepo.findById(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/banks")
    public IscMsBank createBank(@RequestBody IscMsBank bank) {
        if (bank.getLoginMethodType()      == null) bank.setLoginMethodType("DB");
        if (bank.getPermissionMethodType() == null) bank.setPermissionMethodType("DB");
        if (bank.getIsDefault()            == null) bank.setIsDefault("N");
        return bankRepo.save(bank);
    }

    @PutMapping("/banks/{id}")
    public ResponseEntity<IscMsBank> updateBank(@PathVariable Long id, @RequestBody IscMsBank patch) {
        return bankRepo.findById(id).map(existing -> {
            if (patch.getName() != null)                  existing.setName(patch.getName());
            if (patch.getDescription() != null)           existing.setDescription(patch.getDescription());
            if (patch.getFiid() != null)                  existing.setFiid(patch.getFiid());
            if (patch.getShortCode() != null)             existing.setShortCode(patch.getShortCode());
            if (patch.getLoginMethodType() != null)       existing.setLoginMethodType(patch.getLoginMethodType());
            if (patch.getPermissionMethodType() != null)  existing.setPermissionMethodType(patch.getPermissionMethodType());
            if (patch.getLdapIp() != null)                existing.setLdapIp(patch.getLdapIp());
            if (patch.getLdapPort() != null)              existing.setLdapPort(patch.getLdapPort());
            if (patch.getBaseDn() != null)                existing.setBaseDn(patch.getBaseDn());
            if (patch.getSearchBaseDn() != null)          existing.setSearchBaseDn(patch.getSearchBaseDn());
            if (patch.getCountryIso2() != null)           existing.setCountryIso2(patch.getCountryIso2());
            if (patch.getSwiftBic() != null)              existing.setSwiftBic(patch.getSwiftBic());
            return ResponseEntity.ok(bankRepo.save(existing));
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/banks/{id}")
    public ResponseEntity<Void> softDeleteBank(@PathVariable Long id) {
        return bankRepo.findById(id).map(existing -> {
            existing.setRecordStatus("N");
            bankRepo.save(existing);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }

    // ---- branches ----

    @GetMapping("/banks/{bankId}/branches")
    public List<IscMsBranch> listBranches(@PathVariable Long bankId) {
        return branchRepo.findByBankRecId(bankId);
    }

    @PostMapping("/banks/{bankId}/branches")
    public IscMsBranch createBranch(@PathVariable Long bankId, @RequestBody IscMsBranch branch) {
        branch.setBankRecId(bankId);
        return branchRepo.save(branch);
    }

    @PutMapping("/branches/{id}")
    public ResponseEntity<IscMsBranch> updateBranch(@PathVariable Long id, @RequestBody IscMsBranch patch) {
        return branchRepo.findById(id).map(existing -> {
            if (patch.getName() != null)         existing.setName(patch.getName());
            if (patch.getDescription() != null)  existing.setDescription(patch.getDescription());
            if (patch.getCity() != null)         existing.setCity(patch.getCity());
            if (patch.getRegion() != null)       existing.setRegion(patch.getRegion());
            if (patch.getCountryIso2() != null)  existing.setCountryIso2(patch.getCountryIso2());
            return ResponseEntity.ok(branchRepo.save(existing));
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/branches/{id}")
    public ResponseEntity<Void> softDeleteBranch(@PathVariable Long id) {
        return branchRepo.findById(id).map(existing -> {
            existing.setRecordStatus("N");
            branchRepo.save(existing);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }
}
