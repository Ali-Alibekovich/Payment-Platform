package org.example.authmodule.dto.authorities.response;

import java.util.UUID;

public record GroupCreateResponse(UUID groupId, String groupName) {
}
