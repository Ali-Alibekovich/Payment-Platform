package org.example.authmodule.mapper;

import org.example.authmodule.dto.authorities.response.GroupCreateResponse;
import org.example.authmodule.entity.Group;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface GroupMapper {

    GroupCreateResponse toDto(Group group);
}
