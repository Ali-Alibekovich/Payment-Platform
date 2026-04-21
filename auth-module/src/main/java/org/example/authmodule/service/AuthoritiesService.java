package org.example.authmodule.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authmodule.dto.authorities.response.GroupCreateResponse;
import org.example.authmodule.dto.authorities.response.RoleCreateResponse;
import org.example.authmodule.entity.Group;
import org.example.authmodule.entity.Role;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.mapper.GroupMapper;
import org.example.authmodule.mapper.RoleMapper;
import org.example.authmodule.repository.GroupRepository;
import org.example.authmodule.repository.RoleRepository;
import org.example.authmodule.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthoritiesService {
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final GroupMapper groupMapper;
    private final RoleMapper roleMapper;

    @Transactional
    public GroupCreateResponse createGroup(String groupName) {
        if (groupRepository.existsByGroupName(groupName)) {
            log.warn("Group creation rejected: already exists groupName={}", groupName);
            throw new BusinessException(ErrorCode.GROUP_ALREADY_EXISTS);
        }
        var group = new Group();
        group.setGroupName(groupName);
        group.setRoles(new ArrayList<>());
        group.setUsers(new ArrayList<>());

        var saved = groupRepository.save(group);
        log.info("Group created groupId={} groupName={}", saved.getGroupId(), groupName);
        return groupMapper.toDto(saved);
    }

    @Transactional
    public RoleCreateResponse createRole(String roleName) {
        if (roleRepository.existsRoleByRoleName(roleName)) {
            log.warn("Role creation rejected: already exists roleName={}", roleName);
            throw new BusinessException(ErrorCode.ROLE_ALREADY_EXISTS);
        }
        var role = new Role();
        role.setRoleName(roleName);

        var saved = roleRepository.save(role);
        log.info("Role created roleId={} roleName={}", saved.getRoleId(), roleName);
        return roleMapper.toDto(saved);
    }

    @Transactional
    public void addRoleToGroup(UUID roleId, UUID groupId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> {
                    log.warn("Link role->group failed: role not found roleId={}", roleId);
                    return new BusinessException(ErrorCode.ROLE_OR_GROUP_NOT_FOUND);
                });
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> {
                    log.warn("Link role->group failed: group not found groupId={}", groupId);
                    return new BusinessException(ErrorCode.ROLE_OR_GROUP_NOT_FOUND);
                });

        if (group.getRoles() == null) {
            group.setRoles(new ArrayList<>());
        }

        group.getRoles().add(role);

        groupRepository.save(group);
        log.info("Role attached to group roleId={} groupId={}", roleId, groupId);
    }

    @Transactional
    public void addRoleToUser(UUID roleId, UUID userId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> {
                    log.warn("Link role->user failed: role not found roleId={}", roleId);
                    return new BusinessException(ErrorCode.ROLE_OR_GROUP_NOT_FOUND);
                });
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Link role->user failed: user not found userId={}", userId);
                    return new BusinessException(ErrorCode.USER_NOT_FOUND);
                });

        if (user.getRoles() == null) {
            user.setRoles(new ArrayList<>());
        }

        user.getRoles().add(role);

        userRepository.save(user);
        log.info("Role attached to user roleId={} userId={}", roleId, userId);
    }

    @Transactional
    public void addUserToGroup(UUID userId, UUID groupId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Link user->group failed: user not found userId={}", userId);
                    return new BusinessException(ErrorCode.USER_NOT_FOUND);
                });
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> {
                    log.warn("Link user->group failed: group not found groupId={}", groupId);
                    return new BusinessException(ErrorCode.ROLE_OR_GROUP_NOT_FOUND);
                });

        if (user.getGroups() == null) {
            user.setGroups(new ArrayList<>());
        }
        user.getGroups().add(group);

        userRepository.save(user);
        log.info("User attached to group userId={} groupId={}", userId, groupId);
    }
}
