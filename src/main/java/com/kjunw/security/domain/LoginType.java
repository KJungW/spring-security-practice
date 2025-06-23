package com.kjunw.security.domain;

import java.util.Arrays;

public enum LoginType {
    COMMON("common"),
    NAVER("naver"),
    KAKAO("kakao"),
    GOOGLE("google");

    private final String registrationId;

    LoginType(String registrationId) {
        this.registrationId = registrationId;
    }

    public static LoginType parse(String registrationId) {
        return Arrays.stream(LoginType.values())
                .filter(type -> type.getRegistrationId().equals(registrationId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("잘못된 값으로 로그인 타입을 파싱하고 있습니다."));
    }

    public String getRegistrationId() {
        return registrationId;
    }
}
