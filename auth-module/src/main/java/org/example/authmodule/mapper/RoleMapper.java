package org.example.authmodule.mapper;

import org.example.authmodule.dto.authorities.response.RoleCreateResponse;
import org.example.authmodule.entity.Role;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    RoleCreateResponse toDto(Role user);
}
