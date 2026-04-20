package org.example.authmodule.dto.authorities.response;

import java.util.UUID;

public record RoleCreateResponse(UUID roleId, String roleName) {
}
