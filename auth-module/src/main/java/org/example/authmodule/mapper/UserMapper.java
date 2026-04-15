package org.example.authmodule.mapper;

import org.example.authmodule.dto.UserResponseDto;
import org.example.authmodule.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserResponseDto toDto(User user);
}