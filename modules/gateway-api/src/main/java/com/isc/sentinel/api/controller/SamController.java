package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.auth.AuthService;
import com.isc.sentinel.persistence.entity.*;
import com.isc.sentinel.persistence.repo.*;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin/sam")
@RequiredArgsConstructor
public class SamController {

    private final IscSamActionRepository       actionRepo;
    private final IscSamRoleRepository         roleRepo;
    private final IscSamTeamRepository         teamRepo;
    private final IscSamStaffRepository        staffRepo;
    private final IscSamTeamRoleRepository     teamRoleRepo;
    private final IscSamAccessControlRepository acRepo;

    // ---- actions ----
    @GetMapping("/actions")           public List<IscSamAction> actions()                          { return actionRepo.findAll(); }
    @PostMapping("/actions")          public IscSamAction newAction(@RequestBody IscSamAction a)   { return actionRepo.save(a); }

    // ---- roles ----
    @GetMapping("/banks/{bankId}/roles")  public List<IscSamRole> roles(@PathVariable Long bankId) { return roleRepo.findByMsBankId(bankId); }

    @PostMapping("/banks/{bankId}/roles")
    public IscSamRole createRole(@PathVariable Long bankId, @RequestBody IscSamRole role) {
        role.setMsBankId(bankId);
        return roleRepo.save(role);
    }

    @DeleteMapping("/roles/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        return roleRepo.findById(id).map(r -> {
            r.setRecordStatus("N");
            roleRepo.save(r);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }

    // ---- teams ----
    @GetMapping("/banks/{bankId}/teams")  public List<IscSamTeam> teams(@PathVariable Long bankId) { return teamRepo.findByMsBankId(bankId); }

    @PostMapping("/banks/{bankId}/teams")
    public IscSamTeam createTeam(@PathVariable Long bankId, @RequestBody IscSamTeam team) {
        team.setMsBankId(bankId);
        return teamRepo.save(team);
    }

    // ---- staff ----
    @GetMapping("/banks/{bankId}/staff")
    public List<IscSamStaff> staff(@PathVariable Long bankId) { return staffRepo.findByMsBankId(bankId); }

    @PostMapping("/banks/{bankId}/staff")
    public IscSamStaff createStaff(@PathVariable Long bankId, @RequestBody CreateStaffRequest req) {
        IscSamStaff s = IscSamStaff.builder()
            .msBankId(bankId)
            .samTeamId(req.getSamTeamId())
            .msBranchId(req.getMsBranchId())
            .staffFname(req.getStaffFname())
            .staffLname(req.getStaffLname())
            .staffEmail(req.getStaffEmail())
            .staffLoginname(req.getStaffLoginname())
            .staffLoginpwd(req.getPassword() == null ? null : AuthService.hashDb(req.getStaffLoginname(), req.getPassword()))
            .badLoginpwdCount(0)
            .userStatusCode("ACTIVE")
            .forceChangePwdFlag(req.getPassword() == null ? "Y" : "N")
            .employeeCode(req.getEmployeeCode())
            .build();
        return staffRepo.save(s);
    }

    @PostMapping("/staff/{id}/reset-password")
    public ResponseEntity<Void> resetPassword(@PathVariable Long id, @RequestBody PasswordResetRequest req) {
        return staffRepo.findById(id).map(s -> {
            s.setStaffLoginpwd(AuthService.hashDb(s.getStaffLoginname(), req.getPassword()));
            s.setForceChangePwdFlag("Y");
            s.setBadLoginpwdCount(0);
            s.setUserStatusCode("ACTIVE");
            staffRepo.save(s);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }

    // ---- team↔role binding ----
    @PostMapping("/teams/{teamId}/roles/{roleId}")
    public IscSamTeamRole bindTeamRole(@PathVariable Long teamId, @PathVariable Long roleId) {
        return teamRoleRepo.save(IscSamTeamRole.builder().samTeamId(teamId).samRoleId(roleId).build());
    }

    // ---- accesscontrol (role × menu × action) ----
    @PostMapping("/roles/{roleId}/permissions")
    public IscSamAccessControl grant(@PathVariable Long roleId, @RequestBody GrantRequest req) {
        return acRepo.save(IscSamAccessControl.builder()
            .samRoleId(roleId)
            .samMenuId(req.getMenuId())
            .samActionId(req.getActionId())
            .build());
    }

    @GetMapping("/roles/{roleId}/permissions")
    public List<IscSamAccessControl> permissions(@PathVariable Long roleId) {
        return acRepo.findBySamRoleId(roleId);
    }

    // DTOs

    @Data
    public static class CreateStaffRequest {
        private String staffFname;
        private String staffLname;
        private String staffEmail;
        private String staffLoginname;
        private String password;        // plaintext; hashed before save
        private Long   samTeamId;
        private Long   msBranchId;
        private String employeeCode;
    }

    @Data public static class PasswordResetRequest { private String password; }
    @Data public static class GrantRequest         { private Long menuId; private Long actionId; }
}
