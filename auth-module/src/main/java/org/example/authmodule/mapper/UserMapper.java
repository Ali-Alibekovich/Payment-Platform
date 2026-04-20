package org.example.authmodule.mapper;

import org.example.authmodule.dto.auth.response.UserResponse;
import org.example.authmodule.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserResponse toDto(User user);
}