package org.example.authmodule.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.example.authmodule.dto.ApiResponse;
import org.example.authmodule.dto.authorities.response.GroupCreateResponse;
import org.example.authmodule.dto.authorities.response.RoleCreateResponse;
import org.example.authmodule.service.AuthoritiesService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/authorities")
@RequiredArgsConstructor
public class AuthoritiesController {
    private final AuthoritiesService authoritiesService;

    @PostMapping("/create/group/{groupName}")
    public ResponseEntity<ApiResponse<GroupCreateResponse>> createGroup(
            @PathVariable("groupName") @Valid @NotBlank String groupName
    ) {
        var groupCreateResponse = authoritiesService.createGroup(groupName);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.of(groupCreateResponse));
    }

    @PostMapping("/create/role/{roleName}")
    public ResponseEntity<ApiResponse<RoleCreateResponse>> createRole(
            @PathVariable("roleName") @Valid @NotBlank String roleName
    ) {
        var roleCreateResponse = authoritiesService.createRole(roleName);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.of(roleCreateResponse));
    }

    @PostMapping("/users/{userId}/groups/{groupId}")
    public ResponseEntity<Void> addUserToGroup(
            @PathVariable("userId") @NotNull UUID userId,
            @PathVariable("groupId") @NotNull UUID groupId
    ) {
        authoritiesService.addUserToGroup(userId, groupId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/roles/{roleId}/groups/{groupId}")
    public ResponseEntity<Void> addRoleToGroup(
            @PathVariable("roleId") @NotNull UUID roleId,
            @PathVariable("groupId") @NotNull UUID groupId
    ) {
        authoritiesService.addRoleToGroup(roleId, groupId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/roles/{roleId}/users/{userId}")
    public ResponseEntity<Void> addRoleToUser(
            @PathVariable("roleId") @NotNull UUID roleId,
            @PathVariable("userId") @NotNull UUID userId
    ) {
        authoritiesService.addRoleToUser(roleId, userId);
        return ResponseEntity.ok().build();
    }


}
