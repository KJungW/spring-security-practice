package com.kjunw.security.dto;

import com.kjunw.security.domain.LoginType;

public record SocialMemberCreationContent(
        LoginType loginType,
        String socialId,
        String nickname,
        String email
) {

    public SocialMemberCreationContent(SocialLoginResult loginResult) {
        this(loginResult.loginType(), loginResult.socialId(), loginResult.nickname(), loginResult.email());
    }
}
