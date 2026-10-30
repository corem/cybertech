package com.portagecybertech.challengeoauth.authorizationserver.demo;

import java.util.List;

public record KeyRotationResponse(String activeKid, List<String> publishedKids) {
}
