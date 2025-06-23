package com.kjunw.security.dto;

import com.kjunw.security.domain.LoginType;

public record SocialLoginResult(
        LoginType loginType,
        String socialId,
        String nickname,
        String email
) {

}
